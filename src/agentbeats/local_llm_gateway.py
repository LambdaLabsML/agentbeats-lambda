# src/agentbeats/local_llm_gateway.py

import os
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

import requests


@dataclass
class LocalLLMConfig:
    base_url: str
    api_key: str
    default_model: str
    model_aliases: Dict[str, str]
    timeout: int = 60


def _load_config_from_env() -> LocalLLMConfig:
    """
    Configuración centralizada del LLM local.
    Se controla 100% vía variables de entorno para que no tengas que
    tocar código al cambiar modelo / puerto.
    """
    base_url = os.getenv("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8010/v1")
    api_key = os.getenv("LOCAL_LM_API_KEY") or os.getenv("LOCAL_LLM_API_KEY") or "local-dev-key"

    # Nombre REAL del modelo que expone tu servidor (p.ej. Qwen, Llama, etc.)
    default_model = os.getenv("LOCAL_LLM_MODEL", "qwen2.5-3b-instruct")

    # Aliases extra en JSON, opcional:
    #   LOCAL_LLM_MODEL_ALIASES='{"openai/gpt-oss-20b": "qwen2.5-3b-instruct"}'
    alias_json = os.getenv("LOCAL_LLM_MODEL_ALIASES", "")
    aliases: Dict[str, str] = {}
    if alias_json:
        try:
            aliases.update(json.loads(alias_json))
        except json.JSONDecodeError:
            # No rompemos si está mal formateado; simplemente lo ignoramos.
            pass

    # Aliases por defecto para el concurso / ejemplos
    if "openai/gpt-oss-20b" not in aliases:
        aliases["openai/gpt-oss-20b"] = default_model
    if "gpt-oss-20b" not in aliases:
        aliases["gpt-oss-20b"] = default_model

    timeout = int(os.getenv("LOCAL_LLM_TIMEOUT", "90"))

    return LocalLLMConfig(
        base_url=base_url,
        api_key=api_key,
        default_model=default_model,
        model_aliases=aliases,
        timeout=timeout,
    )


_CONFIG = _load_config_from_env()


def resolve_model(model: Optional[str]) -> str:
    """
    Resuelve el nombre de modelo solicitado a uno que entienda el servidor local.
    - Si es None, usa el modelo por defecto.
    - Si coincide con un alias (ej. 'openai/gpt-oss-20b'), lo traduce.
    """
    if not model:
        return _CONFIG.default_model
    return _CONFIG.model_aliases.get(model, model)


def chat_completion(
    messages: List[Dict[str, str]],
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
    stream: bool = False,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Llamada genérica al endpoint /v1/chat/completions del servidor local.
    Devuelve el JSON completo de la respuesta.
    """
    model_name = resolve_model(model)
    url = _CONFIG.base_url.rstrip("/") + "/chat/completions"

    headers = {
        "Authorization": f"Bearer {_CONFIG.api_key}",
        "Content-Type": "application/json",
    }

    body: Dict[str, Any] = {
        "model": model_name,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    if extra_body:
        body.update(extra_body)

    resp = requests.post(url, headers=headers, json=body, timeout=_CONFIG.timeout)

    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        # Error legible (aquí suelen venir los 'Invalid API key', 'Model not found', etc.)
        raise RuntimeError(
            f"[Local LLM] HTTP {resp.status_code}:\n{resp.text}"
        ) from e

    if stream:
        # Si algún día quieres streaming, aquí se adapta.
        return resp

    return resp.json()


def chat_completion_text(
    messages: List[Dict[str, str]],
    **kwargs: Any,
) -> str:
    """
    Helper cómodo: devuelve solo el 'content' del primer choice.
    """
    data = chat_completion(messages, **kwargs)
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"[Local LLM] Respuesta inesperada: {data}") from e


def debug_config() -> LocalLLMConfig:
    """
    Por si quieres imprimir la config actual desde algún agente.
    """
    return _CONFIG
