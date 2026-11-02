#!/usr/bin/env python3
"""Prepare version-checked model access; never treat a probe as a benchmark."""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

BASE = "https://openrouter.ai/api/v1"
BASES = {"openrouter": BASE, "deepseek": "https://api.deepseek.com"}
MODELS = {
    "v3": ("deepseek/deepseek-chat", "deepseek-ai/DeepSeek-V3"),
    "v3-0324": ("deepseek/deepseek-chat-v3-0324", "deepseek-ai/DeepSeek-V3-0324"),
    "r1": ("deepseek/deepseek-r1", "deepseek-ai/DeepSeek-R1"),
    "r1-0528": ("deepseek/deepseek-r1-0528", "deepseek-ai/DeepSeek-R1-0528"),
}
DEFAULT_KEY = Path.home() / ".config/iotosbench/openrouter.key"
DEEPSEEK_KEY = Path.home() / ".config/iotosbench/deepseek.key"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Model-service redirects are disabled")


def read_key(path, environment="OPENROUTER_API_KEY"):
    key = os.environ.get(environment, "").strip()
    if not key and path.exists():
        if path.stat().st_mode & 0o077:
            raise ValueError("API key file must be private (mode 600)")
        key = path.read_text().strip()
    if "\n" in key or "\r" in key:
        raise ValueError("Invalid multiline API key")
    return key


def configure_key(path, service="OpenRouter"):
    key = getpass.getpass(service + " API key (hidden): ").strip()
    if not key or "\n" in key or "\r" in key:
        raise ValueError("A nonempty single-line API key is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(key + "\n")
    print("Private key file created; its contents are not printed or copied into evidence.")


def request(path, payload=None, key="", timeout=180, service="openrouter"):
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Expected an API-relative path")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(BASES[service] + path,
        data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        body = error.read(65536)
        if key:
            body = body.replace(key.encode(), b"[REDACTED]")
        error.redacted_response = body.decode("utf-8", errors="replace")
        raise
    # A diagnostic must not archive a credential echoed by a remote error/service.
    if key:
        raw = raw.replace(key.encode(), b"[REDACTED]")
    return json.loads(raw)


def model_status(profile):
    model, expected = MODELS[profile]
    catalog = request("/models")
    item = next((x for x in catalog["data"] if x["id"] == model), None)
    endpoints = request("/models/" + model + "/endpoints") if item else {"data": {"endpoints": []}}
    return {"profile": profile, "requested_model": model, "expected_weight_repository": expected,
        "listed": item is not None,
        "weight_identity_matches_catalog": bool(item and item.get("hugging_face_id") == expected),
        "catalog_entry": item, "endpoint_catalog": endpoints,
        "active_endpoint_count": len(endpoints.get("data", {}).get("endpoints", [])),
        "author_engine": False, "author_checkpoint_confirmed": False}


def official_status(key, model):
    catalog = request("/models", key=key, timeout=30, service="deepseek")
    balance = request("/user/balance", key=key, timeout=30, service="deepseek")
    return {"service": "deepseek", "base_url": BASES["deepseek"], "requested_model": model,
        "catalog": catalog, "listed": any(row["id"] == model for row in catalog["data"]),
        "balance_available": balance["is_available"], "historical_v3_confirmed": False,
        "author_engine": False, "author_checkpoint_confirmed": False, "benchmark_trial": False}


def official_check(command, key, model, output):
    record = {"service": "deepseek", "requested_model": model, "benchmark_trial": False,
              "model_call_attempted": False, "response_received": False,
              "utc": datetime.now(timezone.utc).isoformat()}
    before = time.monotonic()
    try:
        status = official_status(key, model)
        (output / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        record.update(available_models=[row["id"] for row in status["catalog"]["data"]],
                      listed=status["listed"], balance_available=status["balance_available"])
        if command == "probe":
            if not status["listed"] or not status["balance_available"]:
                raise ValueError("Requested model is not listed or balance is unavailable")
            payload = {"model": model, "messages": [{"role": "user", "content": "Reply with exactly READY."}],
                       "thinking": {"type": "disabled"}, "max_tokens": 32, "temperature": 0, "stream": False}
            (output / "probe-request.json").write_text(json.dumps(payload, indent=2) + "\n")
            record["model_call_attempted"] = True
            response = request("/chat/completions", payload, key, timeout=60, service="deepseek")
            (output / "probe-response.json").write_text(json.dumps(response, indent=2) + "\n")
            record.update(response_received=True, returned_model=response.get("model"),
                          system_fingerprint=response.get("system_fingerprint"), usage=response.get("usage"))
            choice = response["choices"][0]
            record.update(reply=choice["message"]["content"], finish_reason=choice["finish_reason"])
            record["probe_passed"] = record["reply"].strip() == "READY" and record["finish_reason"] == "stop"
    except Exception as error:
        record["failure"] = {"type": type(error).__name__, "http_status": getattr(error, "code", None)}
        if hasattr(error, "redacted_response"):
            record["failure"]["redacted_response"] = error.redacted_response
    finally:
        record["wall_s"] = time.monotonic() - before
        (output / "official-check.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("configure-key", "status", "probe"))
    parser.add_argument("--service", choices=BASES, default="openrouter")
    parser.add_argument("--model", help="OpenRouter profile or exact official DeepSeek model ID")
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--provider", help="Explicit provider slug; no automatic fallback")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform == "darwin":
        parser.error("Run this service and retain its records on leon")
    args.key_file = args.key_file or (DEEPSEEK_KEY if args.service == "deepseek" else DEFAULT_KEY)
    if args.command == "configure-key":
        configure_key(args.key_file, "DeepSeek" if args.service == "deepseek" else "OpenRouter")
        return
    if args.output is None:
        parser.error("--output is required")
    args.output.mkdir(parents=True, exist_ok=False)
    if args.service == "deepseek":
        if not args.model:
            parser.error("Specify an exact official --model; no automatic fallback")
        key = read_key(args.key_file, "DEEPSEEK_API_KEY")
        if not key:
            parser.error("Configure a private DeepSeek key on leon")
        result = official_check(args.command, key, args.model, args.output)
        if "failure" in result or (args.command == "probe" and not result.get("probe_passed")):
            raise SystemExit(1)
        return
    args.model = args.model or "v3"
    if args.model not in MODELS:
        parser.error("Choose an OpenRouter model profile: " + ", ".join(MODELS))
    status = model_status(args.model)
    key = read_key(args.key_file)
    status.update(key_configured=bool(key), benchmark_trial=False,
                  probe_invoked=False, utc=datetime.now(timezone.utc).isoformat())
    with (args.output / "status.json").open("x") as stream:
        json.dump(status, stream, indent=2)
        stream.write("\n")
    if args.command == "probe":
        if not key or not status["weight_identity_matches_catalog"] or not status["active_endpoint_count"]:
            parser.error("A private key and a listed matching model with providers are required")
        if not args.provider:
            parser.error("Specify --provider from the recorded endpoint catalog")
        payload = {"model": status["requested_model"], "messages": [
            {"role": "user", "content": "Reply READY."}], "max_tokens": 128, "stream": False,
            "provider": {"order": [args.provider], "allow_fallbacks": False,
                         "data_collection": "deny"}}
        with (args.output / "probe-request.json").open("x") as stream:
            json.dump(payload, stream, indent=2)
        before = time.monotonic()
        probe = {"request": payload, "benchmark_trial": False, "author_engine": False,
                 "model_call_attempted": True, "response_received": False}
        try:
            probe["response"] = request("/chat/completions", payload, key)
            probe["response_received"] = True
        except Exception as error:
            probe["failure"] = {"type": type(error).__name__, "http_status": getattr(error, "code", None)}
            raise
        finally:
            probe["wall_s"] = time.monotonic() - before
            with (args.output / "probe.json").open("x") as stream:
                json.dump(probe, stream, indent=2)
                stream.write("\n")
        status["probe_invoked"] = True
        with (args.output / "final-status.json").open("x") as stream:
            json.dump(status, stream, indent=2)
            stream.write("\n")
    print(json.dumps({k: status[k] for k in ("profile", "requested_model", "listed",
        "weight_identity_matches_catalog", "active_endpoint_count", "key_configured", "probe_invoked")}))


if __name__ == "__main__":
    main()
