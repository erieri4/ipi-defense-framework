"""
Tests for src/layers/tool_privilege.py  —  Layer 4: Tool Privilege Control.
 
These tests exercise the observable contract of the module:
  • TrustContext      — trust ordering, can_call, downgrade, history
  • module helpers    — set_trust_context, downgrade_current_context,
                        set_layer_enabled
  • enforce_trust     — decorator authorization, fail-closed behavior,
                        downgrade-on-output, decisions logging
  • ToolPrivilege     — start_run / end_run lifecycle, analyze() shape,
                        process() return value, disabled-layer behavior
 
No live LLM is needed. The tests stub the permissions YAML through a
fixture and reset module-level state between tests so they stay isolated.
 
Run from project root:
    pytest tests/test_tool_privilege.py -v
"""
 
import pytest
import yaml
 
from src.layers import tool_privilege as tp
from src.layers.tool_privilege import (
    TrustContext,
    ToolPrivilege,
    enforce_trust,
    set_trust_context,
    downgrade_current_context,
    set_layer_enabled,
)
 
 
# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
 
@pytest.fixture
def stub_permissions(tmp_path, monkeypatch):
    """
    Write a controlled tool_permissions.yaml to a temp dir, point the module's
    PERMISSIONS_FILE constant at it, and clear cached state so each test gets
    a fresh load. This isolates the tests from the real config file.
    """
    perms_file = tmp_path / "tool_permissions.yaml"
    perms = {
        "trust_levels": ["none", "untrusted", "trusted"],
        "tools": {
            "read_email": {
                "trust_required": "untrusted",
                "downgrade_on_output": "untrusted",
            },
            "send_email": {
                "trust_required": "trusted",
            },
            "delete_file": {
                "trust_required": "trusted",
            },
            "list_files": {
                "trust_required": "none",
            },
        },
    }
    perms_file.write_text(yaml.safe_dump(perms))
 
    # Redirect the module to the stub file and reset cached state
    monkeypatch.setattr(tp, "PERMISSIONS_FILE", str(perms_file))
    monkeypatch.setattr(tp, "_permissions", None)
    monkeypatch.setattr(tp, "_current_trust_context", None)
    tp._decisions_log.clear()
    set_layer_enabled(True)
 
    yield perms_file
 
    # Cleanup after test
    monkeypatch.setattr(tp, "_current_trust_context", None)
    tp._decisions_log.clear()
 
 
# ---------------------------------------------------------------------------
# 1. TrustContext — pure logic, no globals
# ---------------------------------------------------------------------------
 
class TestTrustContext:
    """Unit tests for the TrustContext class in isolation."""
 
    def test_init_rejects_none(self):
        with pytest.raises(ValueError):
            TrustContext(None)
 
    def test_init_rejects_single_level(self):
        with pytest.raises(ValueError):
            TrustContext(["only_one"])
 
    def test_init_starts_at_highest_level(self):
        # Highest level = last element in the list
        ctx = TrustContext(["none", "untrusted", "trusted"])
        assert ctx.current() == "trusted"
 
    def test_can_call_at_or_below_current(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        assert ctx.can_call("trusted") is True
        assert ctx.can_call("untrusted") is True
        assert ctx.can_call("none") is True
 
    def test_can_call_after_downgrade(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        ctx.downgrade("untrusted")
        # After downgrade to untrusted, can no longer call trusted-required tools
        assert ctx.can_call("trusted") is False
        assert ctx.can_call("untrusted") is True
        assert ctx.can_call("none") is True
 
    def test_can_call_rejects_unknown_level(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        with pytest.raises(ValueError):
            ctx.can_call("super_admin")
 
    def test_downgrade_to_lower_succeeds(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        assert ctx.downgrade("untrusted", reason="tool returned data") is True
        assert ctx.current() == "untrusted"
 
    def test_downgrade_to_same_level_is_noop(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        assert ctx.downgrade("trusted") is False
        assert ctx.current() == "trusted"
 
    def test_downgrade_cannot_increase_trust(self):
        """Once downgraded, downgrade() cannot raise the level again."""
        ctx = TrustContext(["none", "untrusted", "trusted"])
        ctx.downgrade("none", reason="layer 1 detection")
        assert ctx.downgrade("trusted") is False
        assert ctx.current() == "none"
 
    def test_downgrade_rejects_unknown_level(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        with pytest.raises(ValueError):
            ctx.downgrade("ghost_level")
 
    def test_history_records_each_downgrade(self):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        ctx.downgrade("untrusted", reason="read_email output")
        ctx.downgrade("none", reason="layer1 regex match")
        assert ctx.history() == [
            ("trusted", "untrusted", "read_email output"),
            ("untrusted", "none", "layer1 regex match"),
        ]
 
    def test_history_returns_a_copy(self):
        """Mutating the returned list must not affect internal state."""
        ctx = TrustContext(["none", "untrusted", "trusted"])
        ctx.downgrade("untrusted", reason="x")
        h = ctx.history()
        h.clear()
        assert ctx.history() == [("trusted", "untrusted", "x")]
 
 
# ---------------------------------------------------------------------------
# 2. enforce_trust decorator
# ---------------------------------------------------------------------------
 
class TestEnforceTrust:
    """Tests for the enforce_trust decorator factory."""
 
    def test_unknown_tool_raises_at_decoration_time(self, stub_permissions):
        with pytest.raises(ValueError):
            @enforce_trust("nonexistent_tool")
            def f():
                return "ok"
 
    def test_fail_closed_when_no_context(self, stub_permissions):
        """If no TrustContext is active, calls return an error dict."""
        @enforce_trust("read_email")
        def read_email(eid):
            return f"body {eid}"
 
        # No context set — must fail closed, not crash, not execute the tool
        result = read_email("msg1")
        assert isinstance(result, dict)
        assert result["error"] == "no_trust_context"
        assert result["tool"] == "read_email"
 
    def test_allowed_call_executes_and_logs(self, stub_permissions):
        @enforce_trust("read_email")
        def read_email(eid):
            return f"body {eid}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()  # starts at "trusted" — top level
 
        result = read_email("msg1")
        assert result == "body msg1"
 
        # One allow entry in the decisions log
        assert len(tp._decisions_log) == 1
        entry = tp._decisions_log[0]
        assert entry["tool"] == "read_email"
        assert entry["decision"] == "allowed"
        assert entry["required"] == "untrusted"
        # current_at_call captured BEFORE the downgrade-on-output ran
        assert entry["current_at_call"] == "trusted"
 
    def test_blocked_call_returns_error_and_logs(self, stub_permissions):
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        # Downgrade so that send_email (requires "trusted") is now denied
        downgrade_current_context("untrusted", reason="simulated layer 1")
 
        result = send_email("a@b.com", "hi")
        assert isinstance(result, dict)
        assert result["error"] == "permission_denied"
        assert result["tool"] == "send_email"
        assert result["required"] == "trusted"
        assert result["current_at_call"] == "untrusted"
 
        assert len(tp._decisions_log) == 1
        assert tp._decisions_log[0]["decision"] == "blocked"
 
    def test_downgrade_on_output_is_applied(self, stub_permissions):
        """read_email has downgrade_on_output: untrusted — after a successful
        call, the context must drop to 'untrusted'."""
        @enforce_trust("read_email")
        def read_email(eid):
            return f"body {eid}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        assert tp._current_trust_context.current() == "trusted"
 
        read_email("msg1")
        assert tp._current_trust_context.current() == "untrusted"
 
    def test_downgrade_on_output_cascades(self, stub_permissions):
        """After read_email drops trust to untrusted, send_email (requires
        trusted) must be blocked."""
        @enforce_trust("read_email")
        def read_email(eid):
            return f"body {eid}"
 
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
 
        # First call: allowed, drops trust to untrusted
        read_email("msg1")
        # Second call: blocked because send_email requires trusted
        result = send_email("a@b.com", "hi")
        assert isinstance(result, dict)
        assert result["error"] == "permission_denied"
 
    def test_layer_disabled_bypasses_enforcement(self, stub_permissions):
        """When set_layer_enabled(False), the decorator becomes a no-op."""
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        # Layer disabled — no context, would normally fail closed.
        # With enforcement off, the call must go through.
        set_layer_enabled(False)
        result = send_email("a@b.com", "hi")
        assert result == "sent to a@b.com"
        # Re-enable for other tests
        set_layer_enabled(True)
 
    def test_tool_without_downgrade_does_not_change_trust(self, stub_permissions):
        """list_files has no downgrade_on_output — context stays the same."""
        @enforce_trust("list_files")
        def list_files():
            return ["a.txt"]
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        assert tp._current_trust_context.current() == "trusted"
        list_files()
        assert tp._current_trust_context.current() == "trusted"
 
 
# ---------------------------------------------------------------------------
# 3. Module-level helpers
# ---------------------------------------------------------------------------
 
class TestModuleHelpers:
 
    def test_set_trust_context_sets_global(self, stub_permissions):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        set_trust_context(ctx)
        assert tp._current_trust_context is ctx
        # Reset
        set_trust_context(None)
        assert tp._current_trust_context is None
 
    def test_downgrade_with_no_context_is_safe_noop(self, stub_permissions):
        """Calling downgrade_current_context without an active context must
        return False and not raise."""
        set_trust_context(None)
        result = downgrade_current_context("none", reason="orphan call")
        assert result is False
 
    def test_downgrade_with_active_context_works(self, stub_permissions):
        ctx = TrustContext(["none", "untrusted", "trusted"])
        set_trust_context(ctx)
        assert downgrade_current_context("untrusted", reason="x") is True
        assert ctx.current() == "untrusted"
 
 
# ---------------------------------------------------------------------------
# 4. ToolPrivilege class — lifecycle and analyze()
# ---------------------------------------------------------------------------
 
class TestToolPrivilegeLifecycle:
 
    def test_init_loads_trust_levels(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        assert layer._trust_levels == ["none", "untrusted", "trusted"]
        assert layer.name == "ToolPrivilege"
        assert layer.enabled is True
 
    def test_start_run_creates_fresh_context(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        assert tp._current_trust_context is not None
        assert tp._current_trust_context.current() == "trusted"
        assert tp._decisions_log == []
 
    def test_start_run_clears_previous_log(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        tp._decisions_log.append({"tool": "x", "decision": "allowed",
                                  "required": "none", "current_at_call": "trusted"})
        layer.start_run()  # should clear the log
        assert tp._decisions_log == []
 
    def test_end_run_clears_context(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        layer.end_run()
        assert tp._current_trust_context is None
        assert layer._context is None
 
 
class TestToolPrivilegeAnalyze:
 
    def test_analyze_when_disabled(self, stub_permissions):
        layer = ToolPrivilege(enabled=False)
        result = layer.analyze()
        assert result["status"] == "skipped"
        assert result["blocked"] is False
        assert result["checks"] == []
 
    def test_analyze_without_run_returns_error(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        # No start_run() called, no decisions logged
        result = layer.analyze()
        assert result["status"] == "error"
        assert result["blocked"] is False
        assert "active run" in result["detail"]
 
    def test_analyze_with_no_tool_calls(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        result = layer.analyze()
        assert result["status"] == "passed"
        assert result["blocked"] is False
        assert result["checks"] == []
        assert "no tool calls" in result["detail"].lower()
 
    def test_analyze_with_only_allows(self, stub_permissions):
        @enforce_trust("list_files")
        def list_files():
            return []
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        list_files()
        list_files()
 
        result = layer.analyze()
        assert result["status"] == "passed"
        assert result["blocked"] is False
        # One unique tool — aggregated into a single check
        assert len(result["checks"]) == 1
        check = result["checks"][0]
        assert check["name"] == "list_files"
        assert check["status"] == "allowed"
        assert "2 allowed" in check["detail"]
 
    def test_analyze_with_only_blocks(self, stub_permissions):
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        downgrade_current_context("untrusted", reason="forced")
        send_email("a@b.com", "hi")
 
        result = layer.analyze()
        assert result["status"] == "blocked"
        assert result["blocked"] is True
        assert len(result["checks"]) == 1
        assert result["checks"][0]["status"] == "blocked"
 
    def test_analyze_with_mixed_allow_and_block_for_same_tool(self, stub_permissions):
        """If the same tool is sometimes allowed and sometimes blocked
        during a run, the per-tool status should be 'mixed'."""
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        # First call: allowed (still at "trusted")
        send_email("a@b.com", "hi")
        # Drop trust, then call again: blocked
        downgrade_current_context("untrusted", reason="layer 1 trip")
        send_email("a@b.com", "hi again")
 
        result = layer.analyze()
        assert result["status"] == "blocked"  # overall: any block makes it blocked
        assert result["blocked"] is True
        assert len(result["checks"]) == 1
        check = result["checks"][0]
        assert check["status"] == "mixed"
        assert "1 allowed" in check["detail"]
        assert "1 blocked" in check["detail"]
 
    def test_analyze_aggregates_per_tool(self, stub_permissions):
        @enforce_trust("list_files")
        def list_files():
            return []
 
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        list_files()
        downgrade_current_context("untrusted", reason="x")
        send_email("a@b.com", "hi")
 
        result = layer.analyze()
        assert len(result["checks"]) == 2
        names = sorted(c["name"] for c in result["checks"])
        assert names == ["list_files", "send_email"]
 
    def test_analyze_includes_trust_history(self, stub_permissions):
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        downgrade_current_context("untrusted", reason="layer 1 match")
        result = layer.analyze()
        assert result["trust_history"] == [
            ("trusted", "untrusted", "layer 1 match")
        ]
 
    def test_analyze_returns_required_keys(self, stub_permissions):
        """Sanity check on result dict shape — same contract as other layers."""
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        result = layer.analyze()
        for key in [
            "input", "output", "status", "detail",
            "checks", "blocked", "trust_history", "decisions_log",
        ]:
            assert key in result, f"missing key: {key}"
 
 
class TestToolPrivilegeProcess:
 
    def test_process_returns_false_when_nothing_blocked(self, stub_permissions):
        @enforce_trust("list_files")
        def list_files():
            return []
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        list_files()
        assert layer.process() is False
 
    def test_process_returns_true_when_something_blocked(self, stub_permissions):
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        downgrade_current_context("untrusted", reason="x")
        send_email("a@b.com", "hi")
        assert layer.process() is True
 
 
# ---------------------------------------------------------------------------
# 5. Layer 1 → Layer 4 integration  (mirrors the __main__ sanity check)
# ---------------------------------------------------------------------------
 
class TestLayer1ToLayer4Integration:
    """Simulates the cross-layer flow: Layer 1 detects an injection mid-run
    and downgrades the trust context. Layer 4 must then deny all subsequent
    privileged tool calls."""
 
    def test_layer1_downgrade_blocks_all_tools(self, stub_permissions):
        @enforce_trust("read_email")
        def read_email(eid):
            return f"body {eid}"
 
        @enforce_trust("send_email")
        def send_email(to, body):
            return f"sent to {to}"
 
        layer = ToolPrivilege(enabled=True)
        layer.start_run()
        assert tp._current_trust_context.current() == "trusted"
 
        # Layer 1 trips: hard downgrade to "none"
        applied = downgrade_current_context("none", reason="layer 1 regex match")
        assert applied is True
        assert tp._current_trust_context.current() == "none"
 
        # Even read_email (only needs "untrusted") is denied
        r1 = read_email("msg1")
        assert isinstance(r1, dict) and r1["error"] == "permission_denied"
 
        # send_email also denied
        r2 = send_email("a@b.com", "hi")
        assert isinstance(r2, dict) and r2["error"] == "permission_denied"
 
        # Both are recorded as blocked decisions
        assert len(tp._decisions_log) == 2
        assert all(d["decision"] == "blocked" for d in tp._decisions_log)
 
        # Trust history shows the cascade
        assert tp._current_trust_context.history() == [
            ("trusted", "none", "layer 1 regex match")
        ]
 
 
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
 