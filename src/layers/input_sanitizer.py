from src.layers.base import DefenseLayer
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


ATTACK_PATTERNS = [
    r"you are now",
    r"system:",
    r"disregard",
    r"ignore previous",
]

BLOCKED_MESSAGE = "Input contains potentially harmful content and has been blocked."

PROMPT_GUARD_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"


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
        if mode in {"llm", "combined"}:
            self._load_prompt_guard()

    def _load_prompt_guard(self):
        self._device = "cuda" if torch.cuda.is_available() else "cpu"
        self._tokenizer = AutoTokenizer.from_pretrained(PROMPT_GUARD_MODEL)
        self._model = AutoModelForSequenceClassification.from_pretrained(PROMPT_GUARD_MODEL)
        self._model.to(self._device)
        self._model.eval()

    def process(self, text: str) -> str:
        sanitized_text = ' '.join(text.strip().split())
        if self.mode == "regex":
            return self._process_regex(sanitized_text)
        elif self.mode == "llm":
            return self._process_llm(sanitized_text)
        else:
            regex_result = self._process_regex(sanitized_text)
            if regex_result == BLOCKED_MESSAGE:
                return regex_result
            return self._process_llm(sanitized_text)

    def _process_regex(self, text: str) -> str:
        for pattern in ATTACK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                print(f"[regex] Match found: {pattern}")
                return BLOCKED_MESSAGE
        return text

    def _process_llm(self, text: str) -> str:
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self._device)

        with torch.no_grad():
            logits = self._model(**inputs).logits

        probs = torch.softmax(logits, dim=-1)
        # Prompt Guard 2 is binary: index 0 = benign, index 1 = malicious.
        malicious_prob = probs[0, 1].item()

        if malicious_prob >= self.threshold:
            print(f"[prompt-guard-2] Injection detected (p={malicious_prob:.3f})")
            return BLOCKED_MESSAGE
        return text
