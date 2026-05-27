"""
Layer 3: Output Firewall (The Judge)
------------------------------------

Calls any OpenAI-compatible endpoint. Configured via JUDGE_API_BASE and JUDGE_MODEL env vars.
"""

from __future__ import annotations

import json as _json
import logging
import os
import re
import time
import urllib.request
from typing import Optional

import openai

from src.layers.base import DefenseLayer
from src.utils.prompts import JUDGE_PROMPT_TEMPLATE

_DEFAULT_API_BASE = "http://localhost:11434/v1"
_DEFAULT_MODEL = "qwen3:30b"

logger = logging.getLogger(__name__)

# Hard cap on how much of tool_args we serialize into the prompt.
# Long blobs blow up context and slow the judge; truncation is fine because
# the judge only needs the gist of the proposed action.
_MAX_TOOL_ARGS_CHARS = 800

# Hard cap on tool_output context fed to the judge (when provided).
_MAX_TOOL_OUTPUT_CHARS = 1500

# Verdict parser. We grab the LAST match in the response so that a
# DeepSeek-R1 <think>...VERDICT: ALLOW...</think> followed by a final
# VERDICT: BLOCK is parsed correctly (final answer wins).
_VERDICT_RE = re.compile(r"VERDICT:\s*(ALLOW|BLOCK)", re.IGNORECASE)


class OutputFirewall(DefenseLayer):
    """
    Post-agent judge. Given (user_query, proposed_tool_call, optional tool_output),
    asks a local LLM whether executing the tool call is consistent with the
    user's original intent. Returns ALLOW or BLOCK.

    Fail-closed: if the model is unreachable or its response cannot be parsed,
    the result is reported as `status="error"` and `blocked=True`. The pipeline
    must surface this so we can separate "blocked by judge" from "blocked by
    infrastructure" when computing ASR / Benign Utility.
    """

    def __init__(
        self,
        enabled: bool = True,
        judge_model_name: Optional[str] = None,
        api_base: Optional[str] = None,
        temperature: float = 0.0,
        num_predict: int = 2048,
        request_timeout_s: float = 60.0,
        max_retries: int = 1,
    ):
        super().__init__(name="OutputFirewall", enabled=enabled)

        self.judge_model_name = judge_model_name or os.environ.get("JUDGE_MODEL", _DEFAULT_MODEL)
        if not self.judge_model_name:
            raise ValueError("judge_model_name must be a non-empty string.")

        self.temperature = temperature
        self.num_predict = num_predict
        self.request_timeout_s = request_timeout_s
        self.max_retries = max_retries

        self._api_base = api_base or os.environ.get("JUDGE_API_BASE", _DEFAULT_API_BASE)
        self._client = openai.OpenAI(
            base_url=self._api_base,
            api_key=os.environ.get("JUDGE_API_KEY", "ollama"),
            timeout=request_timeout_s,
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def process(
        self,
        user_query: str,
        tool_name: str,
        tool_args: Optional[dict] = None,
        tool_output: Optional[str] = None,
    ) -> str:
        return self.analyze(user_query, tool_name, tool_args, tool_output)["verdict"]

    def analyze(
        self,
        user_query: str,
        tool_name: str,
        tool_args: Optional[dict] = None,
        tool_output: Optional[str] = None,
    ) -> dict:
        t0 = time.perf_counter()

        prompt = self._build_prompt(user_query, tool_name, tool_args, tool_output)

        # Call the judge with retry. Any exception here is captured and
        # surfaced as an "error" status by _build_result.
        response_text: Optional[str] = None
        call_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            try:
                response_text = self._call_judge(prompt)
                break
            except Exception as exc:  # noqa: BLE001 — we want to log everything
                call_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Layer 3 judge call failed (attempt %d/%d): %s",
                    attempt + 1,
                    self.max_retries + 1,
                    call_error,
                )
                # Brief backoff before retry, but only if we have retries left
                if attempt < self.max_retries:
                    time.sleep(0.5)

        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Parse verdict
        verdict: Optional[str] = None
        reasoning_trace: Optional[str] = response_text
        parse_error: Optional[str] = None

        if response_text is not None:
            try:
                verdict = self._parse_verdict(response_text)
            except ValueError as exc:
                parse_error = str(exc)
                logger.warning("Layer 3 verdict parse failed: %s", parse_error)

        return self._build_result(
            user_query=user_query,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_output=tool_output,
            verdict=verdict,
            reasoning_trace=reasoning_trace,
            latency_ms=latency_ms,
            call_error=call_error,
            parse_error=parse_error,
        )

    # ------------------------------------------------------------------ #
    # Prompt construction
    # ------------------------------------------------------------------ #
    def _build_prompt(
        self,
        user_query: Optional[str],
        tool_name: Optional[str],
        tool_args: Optional[dict],
        tool_output: Optional[str],
    ) -> str:
        if user_query is None:
            logger.warning("Layer 3: user_query is None; using placeholder.")
            user_query = "[empty]"
        if tool_name is None:
            logger.warning("Layer 3: tool_name is None; using placeholder.")
            tool_name = "[empty]"
        if tool_args is None:
            tool_args = {}

        tool_args_str = repr(tool_args)
        if len(tool_args_str) > _MAX_TOOL_ARGS_CHARS:
            tool_args_str = tool_args_str[:_MAX_TOOL_ARGS_CHARS] + " ...[truncated]"

        # tool_output is optional. The professor's spec emphasizes semantic
        # injection — those attacks live in tool output, so passing it to the
        # judge meaningfully improves detection. If the prompt template does
        # not contain {tool_output}, we fall back to the 3-arg form.
        format_kwargs = {
            "user_query": user_query,
            "tool_name": tool_name,
            "tool_args": tool_args_str,
        }

        if "{tool_output}" in JUDGE_PROMPT_TEMPLATE:
            if tool_output is None:
                tool_output_str = "[not provided]"
            else:
                tool_output_str = str(tool_output)
                if len(tool_output_str) > _MAX_TOOL_OUTPUT_CHARS:
                    tool_output_str = tool_output_str[:_MAX_TOOL_OUTPUT_CHARS] + " ...[truncated]"
            format_kwargs["tool_output"] = tool_output_str

        return JUDGE_PROMPT_TEMPLATE.format(**format_kwargs)

    # ------------------------------------------------------------------ #
    # Judge call
    # ------------------------------------------------------------------ #
    def _call_judge(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.judge_model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
            max_tokens=self.num_predict,
        )
        content = response.choices[0].message.content
        if not content:
            content = self._call_ollama_native(prompt)
        return content

    def _call_ollama_native(self, prompt: str) -> str:
        base = self._api_base.rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        url = f"{base}/api/chat"
        payload = _json.dumps({
            "model": self.judge_model_name,
            "messages": [{"role": "user", "content": prompt}],
            "think": False,
            "stream": False,
            "options": {"num_predict": self.num_predict, "temperature": self.temperature},
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.request_timeout_s) as resp:
            data = _json.loads(resp.read())
        return data["message"]["content"]

    # ------------------------------------------------------------------ #
    # Verdict parsing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_verdict(response: str) -> str:
        """
        Find the LAST 'VERDICT: ALLOW|BLOCK' in the response and return it
        upper-cased. Raises ValueError if no verdict line is present.

        We take the last occurrence to handle DeepSeek-R1 style traces where
        the model may write a tentative verdict inside <think>...</think>
        and then commit to a final one after.
        """
        matches = list(_VERDICT_RE.finditer(response))
        if not matches:
            raise ValueError("No 'VERDICT: ALLOW|BLOCK' line found in judge response.")
        return matches[-1].group(1).upper()

    # ------------------------------------------------------------------ #
    # Result assembly
    # ------------------------------------------------------------------ #
    def _build_result(
        self,
        user_query: Optional[str],
        tool_name: Optional[str],
        tool_args: Optional[dict],
        tool_output: Optional[str],
        verdict: Optional[str],
        reasoning_trace: Optional[str],
        latency_ms: float,
        call_error: Optional[str],
        parse_error: Optional[str],
    ) -> dict:
        # Status precedence:
        #   - infra failure (call_error) -> "error"
        #   - parse failure -> "error"
        #   - verdict ALLOW -> "passed"
        #   - verdict BLOCK -> "blocked"
        if call_error is not None:
            status = "error"
            detail = f"Judge model call failed: {call_error}"
            error_kind = "infrastructure"
        elif verdict is None:
            status = "error"
            detail = f"Could not parse verdict from judge response: {parse_error}"
            error_kind = "parse"
        elif verdict == "ALLOW":
            status = "passed"
            detail = "Agent action is consistent with user request."
            error_kind = None
        elif verdict == "BLOCK":
            status = "blocked"
            detail = "Agent action is inconsistent with user request and has been blocked."
            error_kind = None
        else:  # defensive — _parse_verdict should not return anything else
            status = "error"
            detail = f"Unrecognized verdict value: {verdict!r}"
            error_kind = "parse"

        # Fail-closed: errors are treated as blocked at the pipeline level.
        # We surface error_kind separately so the eval scripts can compute
        # ASR/Utility excluding infrastructure failures if desired.
        blocked = status in ("blocked", "error")

        if status == "passed":
            output = "ALLOW"
        elif status == "blocked":
            output = "BLOCK"
        else:
            output = "ERROR"

        input_summary = f"tool={tool_name}, args={tool_args}"

        check = {
            "id": "judge-verdict",
            "name": "Security Judge",
            "status": status,
            "detail": f"Verdict: {verdict}" if verdict is not None else detail,
        }

        return {
            "input": input_summary,
            "output": output,
            "status": status,
            "detail": detail,
            "checks": [check],
            "blocked": blocked,
            "verdict": verdict,
            "reasoning_trace": reasoning_trace,
            "judge_model": self.judge_model_name,
            "latency_ms": latency_ms,
            "error_kind": error_kind,         # None | "infrastructure" | "parse"
            "user_query": user_query,         # echoed for pipeline.collect_report filtering
            "tool_name": tool_name,
            "tool_output_provided": tool_output is not None,
        }