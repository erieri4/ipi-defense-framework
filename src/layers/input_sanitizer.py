from src.layers.base import DefenseLayer
import os
import re
from typing import Dict, List
import torch


ATTACK_PATTERNS = [
    r"you are now",
    r"system:",
    r"disregard",
    r"ignore previous",
]

BLOCKED_MESSAGE = "Input contains potentially harmful content and has been blocked."

PROMPT_GUARD_MODEL = "protectai/deberta-v3-base-prompt-injection"


class InputSanitizer(DefenseLayer):

    def __init__(self, enabled: bool = True, mode: str = "regex", threshold: float = 0.5):
        super().__init__(name="InputSanitizer", enabled=enabled)
        if mode not in {"regex", "llm", "combined"}:
            raise ValueError("Invalid mode. Mode should be 'regex', 'llm', or 'combined'.")
        self.mode = mode
        self.threshold = threshold
        self._tokenizer = None
        self._model = None
        self._device = None
        self._model_error = None
        if mode in {"llm", "combined"}:
            self._load_prompt_guard()

    def _load_prompt_guard(self):
        try:
            os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
            os.environ.setdefault("USE_TF", "0")
            os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._device = "cuda" if torch.cuda.is_available() else "cpu"
            self._tokenizer = AutoTokenizer.from_pretrained(PROMPT_GUARD_MODEL)
            self._model = AutoModelForSequenceClassification.from_pretrained(PROMPT_GUARD_MODEL)
            self._model.to(self._device)
            self._model.eval()
            self._model_error = None
        except Exception as exc:
            self._tokenizer = None
            self._model = None
            self._device = None
            self._model_error = str(exc)

    def process(self, text: str) -> str:
        return self.analyze(text)["output"]

    def analyze(self, text: str) -> dict:
        sanitized_text = " ".join(text.strip().split())
        checks = []

        if self.mode in {"regex", "combined"}:
            regex_check = self._run_regex_check(sanitized_text)
            checks.append(regex_check)
            if regex_check["status"] == "blocked":
                if self.mode == "combined":
                    checks.append(
                        {
                            "id": "llm-check",
                            "name": "LLM classifier",
                            "status": "skipped",
                            "detail": "Skipped because regex validation already blocked the prompt.",
                        }
                    )
                return self._build_result(text, BLOCKED_MESSAGE, "blocked", regex_check["detail"], checks)

            if self.mode == "regex":
                return self._build_result(
                    text,
                    sanitized_text,
                    "passed",
                    "Regex screening passed.",
                    checks,
                )

        if self.mode in {"llm", "combined"}:
            llm_check = self._run_llm_check(sanitized_text)
            checks.append(llm_check)

            if llm_check["status"] == "blocked":
                return self._build_result(text, BLOCKED_MESSAGE, "blocked", llm_check["detail"], checks)

            if llm_check["status"] == "error":
                return self._build_result(
                    text,
                    sanitized_text,
                    "error",
                    "The LLM classifier could not complete validation.",
                    checks,
                )

        return self._build_result(
            text,
            sanitized_text,
            "passed",
            "Prompt validated and normalized.",
            checks,
        )

    def _build_result(self, original_text: str, output: str, status: str, detail: str, checks: List[Dict]) -> dict:
        return {
            "input": original_text,
            "normalized_input": " ".join(original_text.strip().split()),
            "output": output,
            "status": status,
            "detail": detail,
            "checks": checks,
            "blocked": status == "blocked",
        }

    def _run_regex_check(self, text: str) -> dict:
        for pattern in ATTACK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                print(f"[regex] Match found: {pattern}")
                return {
                    "id": "regex-check",
                    "name": "Regex validation",
                    "status": "blocked",
                    "detail": f"Matched suspicious pattern: '{pattern}'.",
                }
        return {
            "id": "regex-check",
            "name": "Regex validation",
            "status": "passed",
            "detail": "No suspicious regex pattern matched.",
        }

    def _run_llm_check(self, text: str) -> dict:
        if self._model is None or self._tokenizer is None:
            return {
                "id": "llm-check",
                "name": "LLM classifier",
                "status": "error",
                "detail": self._model_error or "Prompt Guard model is not available.",
            }

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self._device)

        with torch.no_grad():
            logits = self._model(**inputs).logits

        probs = torch.softmax(logits, dim=-1)
        # The classifier is binary: index 0 = safe, index 1 = injection.
        malicious_prob = probs[0, 1].item()

        if malicious_prob >= self.threshold:
            print(f"[prompt-injection-classifier] Injection detected (p={malicious_prob:.3f})")
            return {
                "id": "llm-check",
                "name": "LLM classifier",
                "status": "blocked",
                "detail": f"Prompt Guard flagged the prompt (malicious probability {malicious_prob:.3f}).",
                "score": malicious_prob,
                "threshold": self.threshold,
            }

        return {
            "id": "llm-check",
            "name": "LLM classifier",
            "status": "passed",
            "detail": f"Prompt Guard passed the prompt (malicious probability {malicious_prob:.3f}).",
            "score": malicious_prob,
            "threshold": self.threshold,
        }
