from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.layers.input_sanitizer import BLOCKED_MESSAGE, InputSanitizer
from src.layers.output_firewall import OutputFirewall
from src.layers.prompt_hardening import PromptHardening
from src.layers.tool_privilege import ToolPrivilege
from src.pipeline import DefensePipeline


app = FastAPI(title="IPI Defense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:4173", "http://localhost:4173", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ValidateRequest(BaseModel):
    prompt: str


sanitizer = InputSanitizer(mode="combined")
hardener = PromptHardening(mode="combined")
firewall = OutputFirewall()
tool_privilege = ToolPrivilege()

pipeline = DefensePipeline([sanitizer, hardener, firewall, tool_privilege])


# Frontend → backend layer-name mapping
_FE_IDS = {
    "InputSanitizer": ("input-sanitizer", "Input Sanitizer"),
    "PromptHardening": ("prompt-hardening", "Prompt Hardening"),
    "OutputFirewall": ("output-firewall", "Output Firewall"),
    "ToolPrivilege": ("runtime-tool-privilege", "Runtime Tool Privilege Control"),
}

# Map internal layer statuses to the badge classes the frontend styles.
# Layer 2 reports "applied"; the frontend treats that as a successful pass.
_FE_STATUS = {
    "passed": "passed",
    "applied": "passed",
    "blocked": "blocked",
    "error": "error",
    "skipped": "skipped",
    "allowed": "passed",
    "mixed": "blocked",
}


def _fe_status(internal: str) -> str:
    return _FE_STATUS.get(internal, internal)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": sanitizer._model is not None,
        "model_error": sanitizer._model_error,
    }


@app.post("/validate")
def validate_prompt(payload: ValidateRequest) -> dict:
    prompt = payload.prompt

    pipeline.start_run()
    try:
        guard = pipeline.guard_tool_output(prompt, user_query=prompt)

        # Identify layer results by the keys each layer uniquely produces.
        l1_result = next(
            (r for r in guard["layer_results"] if "normalized_input" in r),
            None,
        )
        l2_result = next(
            (
                r
                for r in guard["layer_results"]
                if "user_query" in r and "verdict" not in r
            ),
            None,
        )

        # Only call Layer 3 if L1 didn't block — otherwise the prompt is gone.
        l3_result = None
        if l1_result is not None and not l1_result["blocked"]:
            hardened_text = guard["output"]
            l3_response = pipeline.check_action(
                user_query=prompt,
                tool_name="respond",
                tool_args={"text": hardened_text},
                tool_output=hardened_text,
            )
            l3_result = (
                l3_response["layer_results"][0]
                if l3_response["layer_results"]
                else None
            )

        l4_result = tool_privilege.analyze()
    finally:
        pipeline.end_run()

    layer_cards = [
        _format_l1(prompt, l1_result),
        _format_l2(l1_result, l2_result),
        _format_l3(l1_result, l3_result),
        _format_l4(l4_result),
    ]

    final_status, final_reply = _resolve_final(l1_result, l2_result, l3_result, l4_result)

    return {
        "layerResults": layer_cards,
        "finalStatus": final_status,
        "finalReply": final_reply,
        "blockedMessage": BLOCKED_MESSAGE,
    }


def _format_l1(prompt: str, result: dict | None) -> dict:
    fe_id, fe_name = _FE_IDS["InputSanitizer"]
    if result is None:
        return _waiting_card(fe_id, fe_name, "Layer not active.", prompt)

    status = _fe_status(result["status"])
    return {
        "id": fe_id,
        "name": fe_name,
        "status": status,
        "summary": _l1_summary(result["status"]),
        "detail": result["detail"],
        "input": result["input"],
        "output": result["output"],
        "checks": result["checks"],
    }


def _format_l2(l1_result: dict | None, result: dict | None) -> dict:
    fe_id, fe_name = _FE_IDS["PromptHardening"]
    if l1_result is not None and l1_result["blocked"]:
        return _waiting_card(
            fe_id,
            fe_name,
            "Skipped because Layer 1 blocked the prompt.",
            "",
            "Hardening is only applied to prompts that pass the input sanitizer.",
            status="skipped",
        )
    if result is None:
        return _waiting_card(fe_id, fe_name, "Layer did not run.", "")

    status = _fe_status(result["status"])
    return {
        "id": fe_id,
        "name": fe_name,
        "status": status,
        "summary": _l2_summary(result["status"]),
        "detail": result["detail"],
        "input": result["input"],
        "output": result["output"],
        "checks": result["checks"],
    }


def _format_l3(l1_result: dict | None, result: dict | None) -> dict:
    fe_id, fe_name = _FE_IDS["OutputFirewall"]
    if l1_result is not None and l1_result["blocked"]:
        return _waiting_card(
            fe_id,
            fe_name,
            "Skipped because Layer 1 blocked the prompt.",
            "",
            "The judge only evaluates actions for prompts that made it past Layer 1.",
            status="skipped",
        )
    if result is None:
        return _waiting_card(
            fe_id,
            fe_name,
            "Judge not invoked.",
            "",
            "No proposed action was sent to the firewall.",
            status="waiting",
        )

    status = _fe_status(result["status"])
    return {
        "id": fe_id,
        "name": fe_name,
        "status": status,
        "summary": _l3_summary(result["status"], result.get("verdict")),
        "detail": result["detail"],
        "input": result["input"],
        "output": result["output"],
        "checks": result["checks"],
    }


def _format_l4(result: dict) -> dict:
    fe_id, fe_name = _FE_IDS["ToolPrivilege"]
    status = _fe_status(result["status"])
    return {
        "id": fe_id,
        "name": fe_name,
        "status": status,
        "summary": _l4_summary(result),
        "detail": result["detail"],
        "input": result["input"],
        "output": result["output"],
        "checks": result["checks"],
    }


def _waiting_card(
    fe_id: str,
    fe_name: str,
    summary: str,
    input_text: str,
    detail: str = "",
    status: str = "waiting",
) -> dict:
    return {
        "id": fe_id,
        "name": fe_name,
        "status": status,
        "summary": summary,
        "detail": detail or summary,
        "input": input_text,
        "output": "",
        "checks": [],
    }


def _l1_summary(status: str) -> str:
    if status == "blocked":
        return "Prompt blocked by Layer 1."
    if status == "error":
        return "Prompt could not be fully validated."
    return "Prompt validated and normalized."


def _l2_summary(status: str) -> str:
    if status == "applied":
        return "Hardening techniques applied to the prompt."
    if status == "skipped":
        return "No hardening techniques were applied."
    return f"Layer status: {status}."


def _l3_summary(status: str, verdict: str | None) -> str:
    if status == "passed":
        return "Judge allowed the proposed action."
    if status == "blocked":
        return "Judge blocked the proposed action."
    if status == "error":
        return "Judge could not produce a verdict."
    if verdict:
        return f"Verdict: {verdict}."
    return f"Layer status: {status}."


def _l4_summary(result: dict) -> str:
    history = result.get("trust_history") or []
    if result["status"] == "blocked":
        return "One or more tool calls were blocked."
    if history:
        last = history[-1]
        return f"Trust downgraded to '{last[1]}'."
    return "No tool calls were made during this run."


def _resolve_final(
    l1: dict | None,
    l2: dict | None,
    l3: dict | None,
    l4: dict,
) -> tuple[str, str]:
    if l1 is None:
        return "error", "Validation could not start — Layer 1 did not run."

    if l1["status"] == "error":
        return "error", "Validation could not finish because the Layer 1 classifier is unavailable."

    if l1["blocked"]:
        return "blocked", "Validation stopped at Layer 1. Open the layer card on the right for the exact reason."

    if l3 is not None:
        if l3.get("error_kind") == "infrastructure" or l3["status"] == "error":
            return (
                "error",
                "Layer 3 could not reach the judge model. Make sure Ollama is running with the configured judge.",
            )
        if l3["blocked"]:
            return "blocked", "Layer 3 blocked the proposed action as inconsistent with the user's request."

    if l4.get("blocked"):
        return "blocked", "Layer 4 blocked a tool call that exceeded its allowed trust level."

    return "ready", "Prompt cleared every defense layer."
