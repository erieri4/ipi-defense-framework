

from src.layers.base import DefenseLayer

class DefensePipeline:

    def __init__(self, layers: list[DefenseLayer])-> None:
        self.layers: dict[str, DefenseLayer] = {}
        self._run_log = []
        for layer in layers:
            if layer.name in self.layers: 
                raise ValueError(f"Duplicate layer name detected: {layer.name}.")
            self.layers[layer.name] = layer

    def start_run(self) -> None:
        self._run_log = []
        layer = self._get("ToolPrivilege")
        if layer is not None:
            layer.start_run()

    def end_run(self) -> None:
        layer = self._get("ToolPrivilege")
        if layer is not None:
            layer.end_run()

    def _get(self, layer_name: str) -> DefenseLayer | None:
        if layer_name not in self.layers:
            return None
        elif not self.layers[layer_name].enabled:
            return None
        else:
            return self.layers[layer_name]
        
    def _safe_analyze(self, layer: DefenseLayer, *args) -> dict:
        """
        Call layer.analyze(*args) with fail-closed semantics.
        On any exception, return a synthetic 'blocked' result with the
        exception captured. The pipeline never crashes on a layer bug.
        """
        try:
            return layer.analyze(*args)
        except Exception as e:
            return {
                "input": "<exception>",
                "output": "<layer crashed — treated as blocked>",
                "status": "error",
                "detail": f"{type(e).__name__}: {e}",
                "checks": [],
                "blocked": True,
                "verdict": None,
                "exception": type(e).__name__,
                "exception_message": str(e),
            }
        

    def guard_tool_output(self, text: str, user_query: str = "") -> dict:

        # Sticky note + bookkeeping
        layer_results = []
        last_layer_name = "completed"   # default if nothing runs

        # ─── Section 1: Layer 1 ───
        l1 = self._get("InputSanitizer")
        if l1 is not None:
            # Run it
            l1_result = self._safe_analyze(l1, text)

            # Record what happened
            layer_results.append(l1_result)
            self._run_log.append(l1_result)
            last_layer_name = l1.name      # update the sticky note

            # If L1 blocked → STOP HERE
            if l1_result["blocked"]:
                return {
                    "stage": last_layer_name,
                    "output": l1_result["output"],
                    "blocked": True,
                    "layer_results": layer_results,
                }

            # Otherwise, use L1's cleaned text from now on
            text = l1_result["output"]

    # ─── Section 2: Layer 2 ───
        l2 = self._get("PromptHardening")
        if l2 is not None:
            # Run it (two arguments this time!)
            l2_result = self._safe_analyze(l2, text, user_query)

            # Record what happened
            layer_results.append(l2_result)
            self._run_log.append(l2_result)
            last_layer_name = l2.name      # update the sticky note

            # Use L2's hardened text from now on
            text = l2_result["output"]

        # ─── Section 3: Final return ───
        return {
            "stage": last_layer_name,
            "output": text,
            "blocked": False,
            "layer_results": layer_results,
        }
        
    def check_action(self, user_query: str, tool_name: str, tool_args: dict | None = None) -> dict:
        layer_results = []

        l3 = self._get("OutputFirewall")
        if l3 is not None:
            l3_result = self._safe_analyze(l3, user_query, tool_name, tool_args)

            layer_results.append(l3_result)
            self._run_log.append(l3_result)

            return {
            "stage": l3.name,
            "verdict": l3_result["verdict"],
            "blocked": l3_result["blocked"],
            "layer_results": layer_results,
            }
        
        return {
            "stage": "completed",
            "verdict": None,
            "blocked": False,
            "layer_results": [],
       }
    
    def collect_report(self) -> dict:
        # --- Layer 1: filter _run_log for L1 entries ---
        l1 = self._get("InputSanitizer")
        if l1 is None:
            l1_report = "not_present"
        else:
            entries = [r for r in self._run_log if "normalized_input" in r]
            l1_report = entries if entries else "not_called_during_run"

        # --- Layer 2 ---
        l2 = self._get("PromptHardening")
        if l2 is None:
           l2_report = "not_present"
        else:
           entries = [r for r in self._run_log if "user_query" in r]
           l2_report = entries if entries else "not_called_during_run"

        # --- Layer 3 ---
        l3 = self._get("OutputFirewall")
        if l3 is None:
            l3_report = "not_present"
        else:
            entries = [r for r in self._run_log if "verdict" in r]
            l3_report = entries if entries else "not_called_during_run"

        # --- Layer 4 ---
        l4 = self._get("ToolPrivilege")
        if l4 is None:
           l4_report = "not_present"
        else:
           l4_report = l4.analyze()

        # --- any_blocked ---
        any_blocked = any(r.get("blocked", False) for r in self._run_log)
        if isinstance(l4_report, dict) and l4_report.get("blocked", False):
            any_blocked = True

        return {
            "input_sanitizer":  l1_report,
            "prompt_hardening": l2_report,
            "output_firewall":  l3_report,
            "tool_privilege":   l4_report,
            "per_call_log":     list(self._run_log),
            "any_blocked":      any_blocked,
        }




