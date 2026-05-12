from src.layers.base import DefenseLayer
from typing import  List, Tuple, Optional
from functools import wraps
import yaml


PERMISSIONS_FILE = "config/tool_permissions.yaml"

class TrustContext:

    def __init__(self,trust_levels:list[str]):
        if trust_levels is None or len(trust_levels) < 2:
            raise ValueError("Trust levels must be a list with at least two elements")
        self._trust_levels = trust_levels
        self._current_level = trust_levels[-1]
        self._history = []

    def current(self) -> str:
        return self._current_level

    def can_call(self,required:str)-> bool:
        if required not in self._trust_levels:
            raise ValueError(f"Required trust level '{required}' is not in the defined trust levels")
        current_level_index = self._trust_levels.index(self._current_level)
        required_level_index = self._trust_levels.index(required)
        return current_level_index >= required_level_index
    

    def downgrade(self,target:str,reason: str = "") -> bool:
        if target not in self._trust_levels:
            raise ValueError(f"Target trust level '{target}' is not in the defined trust levels")
        
        current_level_index = self._trust_levels.index(self._current_level)
        target_level_index = self._trust_levels.index(target)
        if target_level_index < current_level_index:
            self._history.append((self._current_level, target, reason))
            self._current_level = target
            return True
        
        else: 
            return False
    

    def history(self) ->List[Tuple[str, str, str]]:
        return list(self._history)
    



_current_trust_context: Optional[TrustContext] = None   # the global
_permissions: dict = None                                # YAML loaded once
_decisions_log: list = []                                # audit trail for eval      
_layer_enabled: bool = True


def _load_permissions() -> dict:
    global _permissions
    if _permissions is not None:
        return _permissions
        
    
    with open(PERMISSIONS_FILE, "r") as f:
        _permissions = yaml.safe_load(f)
    return _permissions
        

def set_trust_context(context: TrustContext) -> None:
    """Called by ToolPrivilege at the start of each agent run."""

    global _current_trust_context
    _current_trust_context = context

def downgrade_current_context(target_level: str, reason: str = "") -> bool:
    """
    Downgrade the active trust context. Called by other layers (e.g. Layer 1)
    when they detect a condition that should reduce trust.
    
    Returns True if the downgrade was applied, False if it was a no-op
    (no active context, or target level not lower than current).
    """
    if _current_trust_context is None:
        return False
    return _current_trust_context.downgrade(target_level, reason=reason)

def set_layer_enabled(enabled: bool) -> None:
    """Toggle Layer 4 enforcement. When False, the decorator becomes a no-op."""
    global _layer_enabled
    _layer_enabled = enabled

def enforce_trust(tool_name: str):
    """Decorator factory."""
    permissions = _load_permissions()
    if tool_name not in permissions["tools"]:
        raise ValueError(f"Tool '{tool_name}' not in {PERMISSIONS_FILE}")

    tool_spec = permissions["tools"][tool_name]
    required = tool_spec["trust_required"]
    downgrade = tool_spec.get("downgrade_on_output")
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not _layer_enabled:
                return func(*args, **kwargs)
            # Step A: get context, fail closed
            context = _current_trust_context
            if context is None:
                
                return {
                    "error": "no_trust_context",
                    "tool": tool_name,
                }
            
            current_at_call = context.current()
            
            
            # Step B: check authorization
            if not context.can_call(required):

                
                
                # Step C: log block
                _decisions_log.append({
                    "tool": tool_name,
                    "decision": "blocked",
                    "required": required,
                    "current_at_call": current_at_call,
                })
                return {
                    "error": "permission_denied",
                    "tool": tool_name,
                    "required": required,
                    "current_at_call": current_at_call,
                }
            
            # Step D: execute the tool
            result = func(*args, **kwargs)
            
            # Step E: downgrade on output if applicable
            if downgrade is not None:
                context.downgrade(downgrade, reason=f"tool '{tool_name}' returned external data")
            
            # Step F: log the allow and return
            _decisions_log.append({
                "tool": tool_name,
                "decision": "allowed",
                "required": required,
                "current_at_call": current_at_call,
            })
            return result
        
        return wrapper
    return decorator

class ToolPrivilege(DefenseLayer):
    def __init__(self, enabled: bool = True):
        super().__init__(
            name="ToolPrivilege",
            enabled=enabled
        )
        permissions = _load_permissions()
        self._trust_levels = permissions["trust_levels"]
        self._context: Optional[TrustContext] = None
        set_layer_enabled(enabled)

    def start_run(self)-> None:
        # Initialize a fresh trust context at the start of each run
        ctx = TrustContext(self._trust_levels)
        set_trust_context(ctx)
        _decisions_log.clear()
        self._context = ctx

    def end_run(self)-> None:
        # Clear context at the end of the run for safety
        set_trust_context(None)
        self._context = None

    def process(self, *args, **kwargs):
        # Placeholder — real implementation in Sub-step 7d
        raise NotImplementedError("process() not yet implemented")
    

    def analyze(self) -> dict:
        # Case 1: layer disabled → skipped (still surface the empty log)
        if not self.enabled:
            return {
                "input": "<agent run summary>",
                "output": "<layer disabled>",
                "status": "skipped",
                "detail": "Tool privilege layer is disabled; no enforcement performed.",
                "checks": [],
                "blocked": False,
                "trust_history": self._context.history() if self._context is not None else [],
                "decisions_log": list(_decisions_log),
            }
        
        # Case 2: no active run and nothing logged → error
        if self._context is None and len(_decisions_log) == 0:
            return {
                "input": "<agent run summary>",
                "output": "<no decisions>",
                "status": "error",
                "detail": "analyze() called without an active run; call start_run() first.",
                "checks": [],
                "blocked": False,
                "trust_history": [],
                "decisions_log": [],
            }

        # Per-tool aggregates: group _decisions_log by tool name
        per_tool: dict = {}
        for entry in _decisions_log:
            tool = entry["tool"]
            decision = entry["decision"]
            if tool not in per_tool:
                per_tool[tool] = {"allowed": 0, "blocked": 0}
            per_tool[tool][decision] += 1

        # Build checks list — one dict per unique tool
        checks = []
        for tool_name, counts in per_tool.items():
            n_allowed = counts["allowed"]
            n_blocked = counts["blocked"]
            if n_blocked == 0:
                tool_status = "allowed"
                detail = f"{n_allowed} allowed"
            elif n_allowed == 0:
                tool_status = "blocked"
                detail = f"{n_blocked} blocked"
            else:
                tool_status = "mixed"
                detail = f"{n_allowed} allowed, {n_blocked} blocked"
            checks.append({
                "id": f"tool-{tool_name}",
                "name": tool_name,
                "status": tool_status,
                "detail": detail,
            })

        # Overall status
        total_allowed = sum(c["allowed"] for c in per_tool.values())
        total_blocked = sum(c["blocked"] for c in per_tool.values())

        if len(_decisions_log) == 0:
            overall_status = "passed"
            overall_detail = "Run completed; no tool calls were made."
            blocked = False
        elif total_blocked > 0:
            overall_status = "blocked"
            overall_detail = f"{total_blocked} tool call(s) blocked, {total_allowed} allowed."
            blocked = True
        else:
            overall_status = "passed"
            overall_detail = f"All {total_allowed} tool call(s) allowed."
            blocked = False

        trust_history = self._context.history() if self._context is not None else []

        return {
            "input": "<agent run summary>",
            "output": f"{total_allowed} allowed, {total_blocked} blocked",
            "status": overall_status,
            "detail": overall_detail,
            "checks": checks,
            "blocked": blocked,
            "trust_history": trust_history,
            "decisions_log": list(_decisions_log),
        }
    
    def process(self) -> bool:
        """Return True if any tool call was blocked during the run."""
        result = self.analyze()
        return result["blocked"]


  
           



