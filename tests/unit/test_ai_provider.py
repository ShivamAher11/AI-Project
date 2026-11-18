import json
from urllib.parse import urlparse

import httpx
import pytest

from ai.provider import AIConfigurationError, AIProviderError, LLMConfig, LLMProvider


def config(**overrides):
    values = {
        "api_key": "test-token",
        "model": "qwen2.5-codebase",
        "base_url": "https://studio-unmapped-vicinity.ngrok-free.dev/v1",
        "consent": True,
        "allowed_hosts": ("studio-unmapped-vicinity.ngrok-free.dev",),
        "timeout_s": 1,
        "max_retries": 0,
    }
    values.update(overrides)
    return LLMConfig(**values)


def test_status_is_enabled_without_exposing_api_key():
    status = LLMProvider(config()).status()
    assert status["enabled"] is True
    assert status["model"] == "qwen2.5-codebase"
    assert status["endpoint_host"] == "studio-unmapped-vicinity.ngrok-free.dev"
    assert "api_key" not in status
    assert "test-token" not in json.dumps(status)


def test_consent_required_even_if_key_is_present():
    provider = LLMProvider(config(consent=False))
    assert provider.status()["enabled"] is False
    with pytest.raises(AIConfigurationError):
        provider.complete([{"role": "user", "content": "hello"}])


def test_endpoint_host_must_be_allowlisted():
    provider = LLMProvider(config(base_url="https://not-allowed.example/v1"))
    with pytest.raises(AIConfigurationError, match="LLM_ALLOWED_HOSTS"):
        provider.complete([{"role": "user", "content": "hello"}])


def test_non_local_http_endpoint_is_rejected():
    provider = LLMProvider(
        config(base_url="http://studio-unmapped-vicinity.ngrok-free.dev/v1")
    )
    with pytest.raises(AIConfigurationError, match="HTTPS"):
        provider.complete([{"role": "user", "content": "hello"}])


def test_openai_compatible_request_and_response():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["ngrok_header"] = request.headers.get("ngrok-skip-browser-warning")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "Connected to Ollama."}}]}
        )

    provider = LLMProvider(config(), transport=httpx.MockTransport(handler))
    result = provider.generate_text(
        system_prompt="System", user_prompt="Check connection", max_tokens=40
    )

    assert result == "Connected to Ollama."
    assert urlparse(seen["url"]).path == "/v1/chat/completions"
    assert seen["auth"] == "Bearer test-token"
    assert seen["ngrok_header"] == "true"
    assert seen["body"]["model"] == "qwen2.5-codebase"
    assert seen["body"]["temperature"] == 0.0
    assert seen["body"]["stream"] is False


def test_reasoning_effort_param_sent_in_body():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}
        )

    provider = LLMProvider(config(), transport=httpx.MockTransport(handler))
    provider.complete(
        [{"role": "user", "content": "hello"}], reasoning_effort="none"
    )
    assert seen["body"]["reasoning_effort"] == "none"


def test_reasoning_effort_from_config_fallback():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}
        )

    provider = LLMProvider(
        config(reasoning_effort="none"), transport=httpx.MockTransport(handler)
    )
    provider.complete([{"role": "user", "content": "hello"}])
    assert seen["body"]["reasoning_effort"] == "none"


def test_reasoning_effort_param_overrides_config():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "ok"}}]}
        )

    provider = LLMProvider(
        config(reasoning_effort="low"), transport=httpx.MockTransport(handler)
    )
    provider.complete(
        [{"role": "user", "content": "hello"}], reasoning_effort="none"
    )
    assert seen["body"]["reasoning_effort"] == "none"


def test_unexpected_response_is_reported_without_leaking_payload():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, json={"not": "a completion"})
    )
    provider = LLMProvider(config(), transport=transport)
    with pytest.raises(AIProviderError, match="unexpected response shape"):
        provider.complete([{"role": "user", "content": "hello"}])


def test_timeout_is_retried_then_reported():
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        raise httpx.TimeoutException("read timed out", request=request)

    provider = LLMProvider(
        config(max_retries=1, timeout_s=1),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(AIProviderError, match="timed out"):
        provider.complete([{"role": "user", "content": "hello"}])
    assert attempts["n"] == 2


def test_429_is_retried_then_succeeds():
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, json={"error": {"message": "rate limited"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = LLMProvider(
        config(max_retries=1), transport=httpx.MockTransport(handler)
    )
    result = provider.complete([{"role": "user", "content": "hello"}])
    assert result == "ok"
    assert attempts["n"] == 2


def test_500_is_not_retried_beyond_max():
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(500, json={"error": {"message": "server error"}})

    provider = LLMProvider(
        config(max_retries=1), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(AIProviderError, match="HTTP 500"):
        provider.complete([{"role": "user", "content": "hello"}])
    assert attempts["n"] == 2


def test_response_format_is_passed_through():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    provider = LLMProvider(config(), transport=httpx.MockTransport(handler))
    provider.generate_structured(
        system_prompt="sys",
        user_prompt="user",
        max_tokens=100,
        response_format={"type": "json_object"},
    )
    assert seen["body"].get("response_format") == {"type": "json_object"}


def test_error_messages_do_not_leak_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "boom"}})

    provider = LLMProvider(
        config(api_key="super-secret-key-12345"), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(AIProviderError, match="HTTP 500") as exc_info:
        provider.complete([{"role": "user", "content": "hello"}])
    assert "super-secret-key-12345" not in str(exc_info.value)


def test_status_redacts_api_key():
    provider = LLMProvider(config(api_key="secret-key-abcdef"))
    status = provider.status()
    assert "api_key" not in status


def test_tunnel_and_bearer_auth_sent_separately():
    """ngrok Basic Auth and PolyStrata Bearer Auth go in separate headers."""
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        seen["proxy_authorization"] = request.headers.get("proxy-authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = LLMProvider(
        config(
            tunnel_username="tunnel-user",
            tunnel_password="tunnel-pass",
        ),
        transport=httpx.MockTransport(handler),
    )
    provider.complete([{"role": "user", "content": "hello"}])
    assert seen["authorization"] == "Bearer test-token"
    assert seen["proxy_authorization"] == "Basic dHVubmVsLXVzZXI6dHVubmVsLXBhc3M="


def test_tunnel_auth_sent_only_when_both_credentials_present():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["proxy_authorization"] = request.headers.get("proxy-authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    # Only username set: no tunnel header.
    provider = LLMProvider(
        config(tunnel_username="tunnel-user", tunnel_password=""),
        transport=httpx.MockTransport(handler),
    )
    provider.complete([{"role": "user", "content": "hello"}])
    assert seen["proxy_authorization"] is None

    # Only password set: no tunnel header.
    provider = LLMProvider(
        config(tunnel_username="", tunnel_password="tunnel-pass"),
        transport=httpx.MockTransport(handler),
    )
    provider.complete([{"role": "user", "content": "hello"}])
    assert seen["proxy_authorization"] is None


def test_status_redacts_tunnel_credentials():
    provider = LLMProvider(
        config(
            api_key="secret-key-abcdef",
            tunnel_username="tunnel-user",
            tunnel_password="tunnel-pass",
        )
    )
    status = provider.status()
    payload = json.dumps(status)
    assert "secret-key-abcdef" not in payload
    assert "tunnel-user" not in payload
    assert "tunnel-pass" not in payload
    assert "api_key" not in status


def test_arbitrary_host_rejected():
    provider = LLMProvider(config(base_url="https://attacker.example/v1"))
    with pytest.raises(AIConfigurationError, match="LLM_ALLOWED_HOSTS"):
        provider.complete([{"role": "user", "content": "hello"}])


def test_public_http_url_rejected():
    provider = LLMProvider(
        config(base_url="http://studio-unmapped-vicinity.ngrok-free.dev/v1")
    )
    with pytest.raises(AIConfigurationError, match="HTTPS"):
        provider.complete([{"role": "user", "content": "hello"}])
