"""Small, bounded OpenAI-compatible client for the API-side AI agent.

The endpoint is configured only through environment variables. The worker never
imports this module or makes outbound LLM requests.

Local providers (localhost/127.0.0.1/::1) run without cloud consent. Remote
providers require deployment-level consent via CONSENT_CLOUD_LLM=true.
"""

from __future__ import annotations

import json
import os
import base64
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
import httpx


class AIConfigurationError(RuntimeError):
    """The AI feature is disabled or its endpoint is not safely configured."""


class AIProviderError(RuntimeError):
    """The configured AI endpoint did not return a usable completion."""


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _positive_float(
    value: str | None, default: float, minimum: float, maximum: float
) -> float:
    try:
        parsed = float(value) if value else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value else default
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    model: str
    base_url: str
    consent: bool
    allowed_hosts: tuple[str, ...]
    timeout_s: float = 30.0
    reasoning_effort: str | None = None
    max_retries: int = 2
    tunnel_username: str | None = None
    tunnel_password: str | None = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        allowed = os.getenv(
            "LLM_ALLOWED_HOSTS",
            "studio-unmapped-vicinity.ngrok-free.dev",
        )
        return cls(
            api_key=os.getenv("LLM_API_KEY", "").strip(),
            model=os.getenv("LLM_MODEL", "qwen2.5-codebase").strip(),
            base_url=os.getenv(
                "LLM_BASE_URL",
                "https://studio-unmapped-vicinity.ngrok-free.dev/v1",
            ).strip(),
            consent=_as_bool(os.getenv("CONSENT_CLOUD_LLM"), default=False),
            allowed_hosts=tuple(
                host.strip().lower().rstrip(".")
                for host in allowed.split(",")
                if host.strip()
            ),
            timeout_s=_positive_float(os.getenv("LLM_TIMEOUT_S"), 30.0, 1.0, 120.0),
            reasoning_effort=os.getenv("LLM_REASONING_EFFORT", "").strip() or None,
            max_retries=_bounded_int(os.getenv("LLM_MAX_RETRIES"), 2, 0, 4),
            tunnel_username=os.getenv("LLM_TUNNEL_USERNAME", "").strip() or None,
            tunnel_password=os.getenv("LLM_TUNNEL_PASSWORD", "").strip() or None,
        )

    @property
    def endpoint_host(self) -> str | None:
        try:
            return urlsplit(self.base_url).hostname
        except ValueError:
            return None

    @property
    def is_local(self) -> bool:
        host = (self.endpoint_host or "").lower().rstrip(".")
        return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local")

    def validate_endpoint(self) -> None:
        try:
            parsed = urlsplit(self.base_url)
        except ValueError as exc:
            raise AIConfigurationError("LLM_BASE_URL is not a valid URL.") from exc
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"https", "http"} or not host:
            raise AIConfigurationError(
                "LLM_BASE_URL must be an HTTP(S) URL with a hostname."
            )
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise AIConfigurationError(
                "LLM_BASE_URL must not contain credentials, a query, or a fragment."
            )
        if host not in self.allowed_hosts:
            raise AIConfigurationError(
                "LLM_BASE_URL hostname is not in LLM_ALLOWED_HOSTS. Add the exact hostname to that setting."
            )
        if parsed.scheme != "https" and not self.is_local:
            raise AIConfigurationError("Non-local AI endpoints must use HTTPS.")

    def disabled_reason(self) -> str | None:
        # Cloud consent is only required for remote endpoints. Local providers
        # (localhost/127.0.0.1/::1/.local) run without cloud consent per SPEC
        # Amendment 1.5 and the AI Member2 guide.
        if not self.is_local and not self.consent:
            return "CONSENT_CLOUD_LLM is not true."
        if not self.api_key:
            return "LLM_API_KEY is missing."
        if not self.model:
            return "LLM_MODEL is missing."
        try:
            self.validate_endpoint()
        except AIConfigurationError as exc:
            return str(exc)
        return None

    @property
    def enabled(self) -> bool:
        return self.disabled_reason() is None


class LLMProvider:
    """Sends bounded chat-completion requests to Ollama or another compatible API."""

    def __init__(
        self,
        config: LLMConfig | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config or LLMConfig.from_env()
        self._transport = transport

    def status(self) -> dict:
        reason = self.config.disabled_reason()
        host = self.config.endpoint_host
        return {
            "enabled": reason is None,
            "provider": "openai-compatible",
            "model": self.config.model or None,
            "endpoint_host": host,
            "reason": reason,
            "local": self.config.is_local,
        }
    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 900,
        temperature: float = 0.0,
        response_format: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        reason = self.config.disabled_reason()
        if reason is not None:
            raise AIConfigurationError(reason)
        self.config.validate_endpoint()

        base_url = self.config.base_url.rstrip("/")
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": max(0.0, min(1.0, float(temperature))),
            "max_tokens": max(1, min(4096, int(max_tokens))),
            "stream": False,
        }
        if reasoning_effort is None:
            reasoning_effort = self.config.reasoning_effort
        if reasoning_effort is not None:
            payload["reasoning_effort"] = reasoning_effort
        if response_format is not None:
            payload["response_format"] = response_format
        url = f"{base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Harmless for normal APIs and suppresses ngrok's free-tier browser page.
            "ngrok-skip-browser-warning": "true",
        }
        # Bearer for PolyStrata; Basic for the ngrok tunnel edge. Sent separately.
        headers["Authorization"] = f"Bearer {self.config.api_key}"
        if self.config.tunnel_username and self.config.tunnel_password:
            credentials = base64.b64encode(
                f"{self.config.tunnel_username}:{self.config.tunnel_password}".encode(
                    "utf-8"
                )
            ).decode("ascii")
            headers["Proxy-Authorization"] = f"Basic {credentials}"
        for attempt in range(self.config.max_retries + 1):
            try:
                with httpx.Client(
                    timeout=self.config.timeout_s, transport=self._transport
                ) as client:
                    response = client.post(url, headers=headers, json=payload)
                if (
                    response.status_code in {408, 429, 500, 502, 503, 504}
                    and attempt < self.config.max_retries
                ):
                    time.sleep(0.25 * (attempt + 1))
                    continue
                if response.status_code >= 400:
                    raise AIProviderError(
                        f"AI endpoint returned HTTP {response.status_code}."
                    )
                try:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                except (ValueError, KeyError, IndexError, TypeError) as exc:
                    raise AIProviderError(
                        "AI endpoint returned an unexpected response shape."
                    ) from exc
                if not isinstance(content, str) or not content.strip():
                    raise AIProviderError("AI endpoint returned an empty completion.")
                return content.strip()
            except AIProviderError:
                raise
            except httpx.TimeoutException as exc:
                if attempt < self.config.max_retries:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise AIProviderError("AI request timed out.") from exc
            except httpx.RequestError as exc:
                if attempt < self.config.max_retries:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise AIProviderError("AI endpoint could not be reached.") from exc
        raise AIProviderError("AI endpoint could not complete the request.")


    def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 900,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        return self.complete(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.0,
            response_format=response_format,
        )

    def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 900,
        response_format: dict[str, Any] | None = None,
    ) -> Any:
        """Return one parsed JSON object from a bounded completion."""
        content = self.generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        return json.loads(content)




class MockProvider:
    """Deterministic in-process provider substitute for unit tests.

    Never calls the network. Configured responses are returned verbatim so
    tests can exercise success, schema-invalid, grounding-invalid, and empty
    paths without a live model.
    """

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def generate_text(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 900,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "max_tokens": max_tokens,
                "response_format": response_format,
            }
        )
        if not self.responses:
            raise AIProviderError("MockProvider has no configured responses.")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 900,
        response_format: dict[str, Any] | None = None,
    ) -> Any:
        """Return one parsed JSON object from a bounded completion."""
        content = self.generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        return json.loads(content)
