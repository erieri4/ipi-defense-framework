from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.layers.input_sanitizer import BLOCKED_MESSAGE, InputSanitizer


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


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": sanitizer._model is not None,
        "model_error": sanitizer._model_error,
    }


@app.post("/validate")
def validate_prompt(payload: ValidateRequest) -> dict:
    result = sanitizer.analyze(payload.prompt)
    layer_status = result["status"]

    if layer_status == "blocked":
        final_status = "blocked"
        final_reply = "Validation stopped at layer 1. Open the layer card on the right for the exact reason."
    elif layer_status == "error":
        final_status = "error"
        final_reply = "Validation could not finish because the Layer 1 classifier is unavailable."
    else:
        final_status = "ready"
        final_reply = "Validation passed the first layer. The prompt is ready for Prompt Hardening when layer 2 is added."

    layer_results = [
        {
            "id": "input-sanitizer",
            "name": "Input Sanitizer",
            "status": layer_status,
            "summary": _build_summary(result),
            "detail": result["detail"],
            "input": result["input"],
            "output": result["output"],
            "checks": result["checks"],
        },
        {
            "id": "prompt-hardening",
            "name": "Prompt Hardening",
            "status": "ready" if layer_status == "passed" else "waiting",
            "summary": "Ready to receive validated prompt." if layer_status == "passed" else "Waiting for layer 1 to pass.",
            "detail": "Layer 2 will receive the validated output next." if layer_status == "passed" else "This layer stays inactive until the sanitizer passes the prompt.",
            "input": result["output"] if layer_status == "passed" else "",
            "output": "",
            "checks": [],
        },
        {
            "id": "output-firewall",
            "name": "Output Firewall",
            "status": "waiting",
            "summary": "Inactive until the agent proposes an action or response.",
            "detail": "This layer will later judge the model output, not the raw prompt.",
            "input": "",
            "output": "",
            "checks": [],
        },
        {
            "id": "runtime-tool-privilege",
            "name": "Runtime Tool Privilege Control",
            "status": "waiting",
            "summary": "Inactive until tool access decisions are needed.",
            "detail": "This layer will later enforce trust-based tool permissions.",
            "input": "",
            "output": "",
            "checks": [],
        },
    ]

    return {
        "layerResults": layer_results,
        "finalStatus": final_status,
        "finalReply": final_reply,
        "blockedMessage": BLOCKED_MESSAGE,
    }


def _build_summary(result: dict) -> str:
    if result["status"] == "blocked":
        return "Prompt blocked by Layer 1."
    if result["status"] == "error":
        return "Prompt could not be fully validated."
    return "Prompt validated and normalized."
