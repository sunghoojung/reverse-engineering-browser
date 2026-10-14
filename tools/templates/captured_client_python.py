"""One reviewed request. Captured inputs are JSON data, never evaluated code."""
import json
import math
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

HTTP_CLIENT = "__REB_PYTHON_CLIENT__"
HTTP_CLIENT_VERSION = "__REB_PYTHON_VERSION__"
CONFIG_VERSION = "reb-python-client-config-v1"
MAX_SAFE_INTEGER = 9007199254740991
INTEGER = re.compile(r"-?(0|[1-9][0-9]*)\Z")
PARAMETER = re.compile(
    r"\s*;\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*"
    r"""(?:(?P<token>[!#$%&'*+.^_`|~0-9A-Za-z-]+)|"(?P<quoted>(?:[^"\\]|\\.)*)")\s*(?=;|$)"""
)
UNKNOWN_OUTCOME = (
    "The server may have processed this request; check its state before another "
    "send. No automatic retry occurred."
)


class ClientError(Exception):
    def __init__(self, code, message, result=None):
        super().__init__(message)
        self.code = code
        self.result = result


class _Number(str):
    pass


def parse_json(text, *, integers_only=False):
    """Bounded unique-key JSON with Unicode and original number-token checks."""
    if len(text.encode("utf-8")) > 1048576:
        raise ValueError("JSON exceeds 1 MiB.")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result

    def constant(_token):
        raise ValueError("Non-finite JSON number.")

    value = json.loads(text, object_pairs_hook=pairs, parse_int=_Number,
                       parse_float=_Number, parse_constant=constant)
    numbers = {}

    def visit(item, depth=0, pointer=""):
        if depth > 64:
            raise ValueError("JSON nesting exceeds 64.")
        if isinstance(item, _Number):
            numbers[pointer] = str(item)
            if integers_only and (not INTEGER.fullmatch(item) or
                                  abs(int(item)) > MAX_SAFE_INTEGER):
                raise ValueError("Request/config numbers require safe integer tokens.")
            number = int(item) if INTEGER.fullmatch(item) else float(item)
            try:
                if not math.isfinite(number):
                    raise ValueError("Non-finite JSON number.")
            except OverflowError as error:
                raise ValueError("Unrepresentable JSON number.") from error
            return number
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")
        elif isinstance(item, list):
            return [visit(child, depth + 1, pointer + "/" + str(index))
                    for index, child in enumerate(item)]
        elif isinstance(item, dict):
            for key in item:
                key.encode("utf-8", errors="strict")
            return {key: visit(child, depth + 1, pointer + "/" +
                               key.replace("~", "~0").replace("/", "~1"))
                    for key, child in item.items()}
        return item

    return visit(value), numbers


def read_json(path, *, integers_only=False):
    with Path(path).open("rb") as source:
        data = source.read(1048577)
    if len(data) > 1048576:
        raise ValueError("JSON exceeds 1 MiB.")
    return parse_json(data.decode("utf-8", errors="strict"),
                      integers_only=integers_only)[0]


def _object(value, allowed):
    return isinstance(value, dict) and set(value).issubset(allowed)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _default(value, fallback):
    return fallback if value is None else value


def _url(value):
    if (not isinstance(value, str) or len(value) > 8192 or
            not value.startswith(("http://", "https://")) or
            any(ord(char) < 33 or ord(char) > 126 for char in value) or
            any(char in value for char in "\\#")):
        raise ValueError("A complete ASCII HTTP(S) URL without controls is required.")
    parsed = urlsplit(value)
    if (not parsed.hostname or parsed.username is not None or
            parsed.password is not None or "%" in parsed.netloc or
            parsed.netloc.endswith(":")):
        raise ValueError("URL credentials, escaped hosts and invalid ports are unsupported.")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port.")
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    if port is not None and (parsed.scheme, port) not in [("http", 80), ("https", 443)]:
        host += ":" + str(port)
    target = parsed.path or "/"
    if "?" in value:
        target += "?" + parsed.query
    return parsed.scheme + "://" + host, target


def request_issues(request):
    issues = []
    keys = {"method", "url", "headers", "body", "timeout_ms"}
    if not _object(request, keys) or set(request) != keys:
        return ["A complete request object with known keys is required."]
    method = request["method"]
    if (not isinstance(method, str) or
            not re.fullmatch(r"[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}", method) or
            method in ["CONNECT", "TRACE", "TRACK"]):
        issues.append("Unsupported uppercase HTTP method.")
    try:
        _url(request["url"])
    except (ValueError, TypeError):
        issues.append("Python requires a complete ASCII HTTP(S) URL without credentials, fragment or controls.")
    forbidden = {
        "authorization", "proxy-authorization", "cookie", "cookie2", "set-cookie",
        "host", "content-length", "connection", "transfer-encoding", "accept-charset",
        "accept-encoding", "access-control-request-headers", "access-control-request-method",
        "date", "dnt", "expect", "keep-alive", "origin", "referer", "te", "trailer",
        "upgrade", "user-agent", "via", "content-encoding",
    }
    headers = request["headers"]
    if not isinstance(headers, list) or len(headers) > 64:
        issues.append("At most 64 complete header pairs are required.")
    else:
        seen, total = set(), 0
        for pair in headers:
            if not isinstance(pair, list) or len(pair) != 2 or any(type(v) is not str for v in pair):
                issues.append("Malformed header pair.")
                continue
            name, value = pair
            lower = name.lower()
            total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
            if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or len(name) > 128 or
                    len(value) > 2048 or value.strip() != value or
                    any(ord(char) < 32 or ord(char) > 126 for char in value)):
                issues.append("Only bounded ASCII header values without surrounding whitespace or controls are supported.")
            if lower in seen:
                issues.append("Duplicate header names are unsupported.")
            seen.add(lower)
            if lower in forbidden or lower.startswith(("sec-", "proxy-")):
                issues.append("Credential, transport, browser-controlled or encoded-body headers require manual reconstruction.")
            if lower in ["x-http-method", "x-http-method-override", "x-method-override"]:
                if any(part.strip().upper() in ["CONNECT", "TRACE", "TRACK"] for part in value.split(",")):
                    issues.append("Unsupported method override.")
            if lower == "content-type":
                media = value.split(";", 1)[0].strip().lower()
                if not re.fullmatch(r"text/[a-z0-9.+-]+|application/(json|[a-z0-9.-]+\+json|xml|[a-z0-9.-]+\+xml|x-www-form-urlencoded|graphql|x-ndjson|ndjson)", media):
                    issues.append("Only recognized UTF-8 text media types are supported.")
                position, charset_seen = len(value.split(";", 1)[0]), False
                while position < len(value):
                    parameter = PARAMETER.match(value, position)
                    if parameter is None:
                        issues.append("Malformed Content-Type parameters are unsupported.")
                        break
                    position = parameter.end()
                    name = parameter[1].lower()
                    if name == "charset":
                        charset = parameter["token"]
                        if charset is None:
                            charset = re.sub(r"\\(.)", r"\1", parameter["quoted"])
                        if charset_seen or not re.fullmatch(r"utf-?8", charset, re.I):
                            issues.append("Exactly one UTF-8 charset declaration is supported.")
                        charset_seen = True
                    elif name.startswith("charset*"):
                        issues.append("Extended or segmented charset declarations are unsupported.")
        if total > 16384:
            issues.append("Header text exceeds 16 KiB.")
    body = request["body"]
    if not isinstance(body, str) or len(body.encode("utf-8")) > 65536:
        issues.append("A complete UTF-8 text body of at most 64 KiB is required.")
    if method in ["GET", "HEAD"] and body != "":
        issues.append("GET and HEAD bodies are unsupported.")
    if not _integer(request["timeout_ms"], 100, 30000):
        issues.append("Timeout must be 100–30000 ms.")
    return list(dict.fromkeys(issues))


def configuration(config, request):
    def fail(message):
        raise ClientError("invalid_config", message)

    if not _object(config, {"configVersion", "allowedOrigin", "request", "transport", "timeoutMs",
                            "redirectPolicy", "cookiePolicy", "responseChecks"}):
        fail("Unknown or malformed client configuration.")
    if config.get("configVersion") != CONFIG_VERSION:
        fail("Use reb-python-client-config-v1; its per-operation timeouts are not an overall deadline.")
    transport = _default(config.get("transport"), {"mode": "standard", "browserProfile": None})
    if not _object(transport, {"mode", "browserProfile"}) or not isinstance(transport.get("mode"), str):
        fail("transport requires a supported mode.")
    if transport["mode"] != "standard":
        raise ClientError("unsupported_transport", "Python supports standard HTTP only. No profile fallback was attempted.")
    if transport.get("browserProfile") is not None:
        raise ClientError("unsupported_profile", "Standard HTTP does not accept a browser profile.")
    timeout = _default(config.get("timeoutMs"), request.get("timeout_ms") if isinstance(request, dict) else None)
    if not _integer(timeout, 100, 30000):
        fail("timeoutMs must be 100–30000 ms.")
    redirect = _default(config.get("redirectPolicy"), "manual")
    if redirect not in ["manual", "error"]:
        fail("redirectPolicy must be manual or error; redirects are never followed.")
    if _default(config.get("cookiePolicy"), "omit") != "omit":
        fail("cookiePolicy must be omit.")
    checks = _default(config.get("responseChecks"), {})
    if not _object(checks, {"statuses", "contentType", "jsonFields"}):
        fail("Malformed responseChecks.")
    statuses = _default(checks.get("statuses"), [])
    media = checks.get("contentType")
    fields = _default(checks.get("jsonFields"), [])
    if (not isinstance(statuses, list) or len(statuses) > 32 or
            any(not _integer(status, 100, 599) for status in statuses) or len(set(statuses)) != len(statuses)):
        fail("statuses must be at most 32 distinct HTTP status integers.")
    if media is not None and (not isinstance(media, str) or len(media) > 128 or
                              not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media)):
        fail("contentType must be a lowercase media type without parameters.")
    if not isinstance(fields, list) or len(fields) > 32:
        fail("At most 32 JSON field checks are supported.")
    for field in fields:
        if not _object(field, {"pointer", "type", "equals"}):
            fail("Malformed JSON field check.")
        pointer, kind = field.get("pointer"), field.get("type")
        if (not isinstance(pointer, str) or len(pointer.encode("utf-8")) > 1024 or
                (pointer != "" and not pointer.startswith("/")) or
                re.search(r"~(?![01])", pointer) or len(pointer.split("/")) > 33):
            fail("Each JSON field requires a bounded RFC 6901 pointer.")
        if kind not in ["null", "boolean", "number", "string", "array", "object"]:
            fail("Each JSON field requires a supported type.")
        if "equals" in field:
            expected = field["equals"]
            valid = (kind == "null" and expected is None or
                     kind == "boolean" and type(expected) is bool or
                     kind == "string" and type(expected) is str and len(expected.encode("utf-8")) <= 2048 or
                     kind == "number" and _integer(expected, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER))
            if not valid:
                fail("equals requires a matching scalar type or safe integer.")
    return {"transport": transport, "timeoutMs": timeout, "timeoutScope": "per-operation",
            "redirectPolicy": redirect, "cookiePolicy": "omit",
            "responseChecks": {"statuses": statuses, "contentType": media, "jsonFields": fields}}


def validate_response(result, policy):
    def fail(code, message):
        raise ClientError(code, message, result)

    checks = policy["responseChecks"]
    configured = bool(checks["statuses"] or checks["contentType"] or checks["jsonFields"])
    result["validation"] = {"configured": configured, "passed": False}
    if policy["redirectPolicy"] == "error" and 300 <= result["status"] <= 399:
        fail("redirect_refused", "Redirect refused; no redirect was followed.")
    if checks["statuses"] and result["status"] not in checks["statuses"]:
        fail("response_status", "Response status does not match the accepted statuses.")
    media = [value.split(";", 1)[0].strip().lower() for name, value in result["headers"] if name.lower() == "content-type"]
    if checks["contentType"] and (len(media) != 1 or media[0] != checks["contentType"]):
        fail("response_content_type", "Response Content-Type does not match.")
    if configured and result["body_truncated"]:
        fail("response_truncated", "An incomplete response cannot pass response checks.")
    if checks["jsonFields"]:
        try:
            if result["body_invalid_utf8"]:
                raise ValueError()
            body, numbers = parse_json(result["body"])
        except (ValueError, UnicodeError, RecursionError):
            fail("response_json", "Response is not complete valid unique-key JSON.")
        for field in checks["jsonFields"]:
            value = body
            for part in ([] if field["pointer"] == "" else field["pointer"].split("/")[1:]):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", part) and len(part) <= 16 and int(part) < len(value):
                    value = value[int(part)]
                elif isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    fail("response_field_missing", "A configured JSON pointer is absent.")
            kind = {type(None): "null", bool: "boolean", int: "number", float: "number",
                    str: "string", list: "array", dict: "object"}.get(type(value))
            if kind != field["type"]:
                fail("response_field_type", "A configured JSON field has the wrong type.")
            if "equals" in field:
                if kind == "number" and (not INTEGER.fullmatch(numbers.get(field["pointer"], "")) or value != field["equals"]):
                    fail("response_field_value", "Numeric equals requires an exact integer JSON token.")
                if value != field["equals"]:
                    fail("response_field_value", "A configured JSON field has an unexpected value.")
    result["validation"]["passed"] = configured
    return result


def _snapshot(result, data, truncated):
    result["body_truncated"] = truncated
    try:
        result["body"] = bytes(data).decode("utf-8", errors="strict")
        result["body_invalid_utf8"] = False
    except UnicodeDecodeError:
        result["body"] = bytes(data).decode("utf-8", errors="replace")
        result["body_invalid_utf8"] = True


def _consume(result, status, headers, chunks):
    result.update(status=status, network_requests=1, headers=[], redirect_followed=False,
                  body="", body_truncated=True, body_invalid_utf8=False)
    size = 0
    for name, value in headers:
        size += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if len(result["headers"]) >= 128 or size > 65536:
            result["headers_truncated"] = True
            raise ClientError("response_read", "Response headers exceed their retained limit.", result)
        result["headers"].append([name, value])
    data = bytearray()
    _snapshot(result, data, False)
    for chunk in chunks:
        remaining = 65536 - len(data)
        data.extend(chunk[:remaining])
        _snapshot(result, data, len(chunk) > remaining)
        if result["body_truncated"]:
            break


def _perform(request, policy, result):
    if HTTP_CLIENT not in ["requests", "httpx"]:
        raise ClientError("unsupported_transport", "Unsupported Python HTTP client.")
    if os.environ.get("SSLKEYLOGFILE"):
        raise ClientError("unsupported_environment", "Disable TLS key logging before using this credential-omitting client.")
    seconds = policy["timeoutMs"] / 1000
    payload = request["body"].encode("utf-8")
    expected_target = _url(request["url"])[1]
    if HTTP_CLIENT == "requests":
        import requests
        if getattr(requests, "__version__", None) != HTTP_CLIENT_VERSION:
            raise ImportError("Use the reviewed provider pin.")
        with requests.Session() as session:
            session.trust_env = False
            session.headers.clear()
            adapter = requests.adapters.HTTPAdapter(max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            prepared = session.prepare_request(requests.Request(request["method"], request["url"],
                headers={"Accept-Encoding": "identity", **dict(request["headers"])}, data=payload))
            if _url(prepared.url)[1] != expected_target:
                raise ClientError("invalid_input", "Requests would normalize the captured target; supply a deliberately reviewed URL.")
            # Direct adapter.send avoids Session's hidden redirect-response drain
            # even when allow_redirects=False, retaining a bounded streamed body.
            result["network_attempted"] = True
            with adapter.send(prepared, stream=True, timeout=(seconds, seconds), verify=True, proxies={}) as response:
                _consume(result, response.status_code, response.raw.headers.iteritems(),
                         response.raw.stream(8192, decode_content=False))
    else:
        import httpx
        if getattr(httpx, "__version__", None) != HTTP_CLIENT_VERSION:
            raise ImportError("Use the reviewed provider pin.")
        transport = httpx.HTTPTransport(verify=True, trust_env=False, retries=0)
        with httpx.Client(transport=transport, trust_env=False, follow_redirects=False,
                          timeout=seconds, headers={"Accept-Encoding": "identity"}) as session:
            prepared = session.build_request(request["method"], request["url"],
                headers=dict(request["headers"]), content=payload)
            if prepared.url.raw_path.decode("ascii") != expected_target:
                raise ClientError("invalid_input", "HTTPX would normalize the captured target; supply a deliberately reviewed URL.")
            result["network_attempted"] = True
            response = session.send(prepared, stream=True, follow_redirects=False)
            try:
                _consume(result, response.status_code,
                         ((key.decode("latin-1"), value.decode("latin-1")) for key, value in response.headers.raw),
                         response.iter_raw())
            finally:
                response.close()


def send_request(input_request, *, config=None, send=False, provenance=None):
    config = {} if config is None else config
    provenance = {} if provenance is None else provenance
    request = _default(config.get("request"), input_request) if isinstance(config, dict) else input_request
    try:
        problems = request_issues(request)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        problems = ["Request contains invalid text or values."]
    policy, config_error = None, None
    try:
        policy = configuration(config, request)
    except ClientError as error:
        config_error = error
        problems.append(str(error))
    except (ValueError, TypeError, UnicodeError, OverflowError):
        config_error = ClientError("invalid_config", "Configuration contains invalid text or values.")
        problems.append(str(config_error))
    if (not isinstance(config, dict) or config.get("request") is None) and (
            not isinstance(provenance, dict) or provenance.get("format") != "reb-client-project-v1" or
            provenance.get("mode") != "raw" or provenance.get("problems")):
        problems.append("Provide a complete reviewed config.request; exported evidence is redacted or unsupported.")
    if send is not True:
        return {"dry_run": True, "network_requests": 0, "ready": not problems,
                "problems": problems, "method": request.get("method") if isinstance(request, dict) else None,
                "policy": policy, "instruction": "Review evidence and Python configuration before --send."}
    if config_error:
        raise config_error
    if problems:
        raise ClientError("invalid_input", " ".join(problems))
    if config.get("allowedOrigin") != _url(request["url"])[0]:
        raise ClientError("wrong_origin", "allowedOrigin must exactly match the reviewed origin.")
    result = {"network_attempted": False, "network_requests": 0, "url": request["url"],
              "instruction": UNKNOWN_OUTCOME, "http_client": HTTP_CLIENT,
              "timeout_scope": "per-operation"}
    try:
        _perform(request, policy, result)
        return validate_response(result, policy)
    except ClientError:
        raise
    except ImportError as error:
        raise ClientError("missing_dependency", "Install the reviewed requirements.txt before sending.") from error
    except Exception as error:
        if result["network_attempted"] and not result.get("status"):
            result["network_requests"] = None
        if result.get("status"):
            result["body_truncated"] = True
        # Exception names are classified, never printed with URLs or raw values.
        timeout = "timeout" in type(error).__name__.lower()
        raise ClientError("timeout" if timeout else "response_read" if result.get("status") else "network",
                          "A transport operation timed out." if timeout else "Transport failed; the server outcome may be unknown.", result) from error


def main():
    if sys.argv[1:] not in [[], ["--send"]]:
        raise ValueError("Usage: python client.py [--send]")
    root = Path(__file__).resolve().parent
    request = read_json(root / "requests/request-001.json", integers_only=True)
    provenance = read_json(root / "provenance.json")
    try:
        config = read_json(root / "config.json", integers_only=True)
    except FileNotFoundError:
        config = {}
    print(json.dumps(send_request(request, config=config, provenance=provenance,
                                  send=sys.argv[1:] == ["--send"]), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except ClientError as failure:
        print(failure.code + ": " + str(failure), file=sys.stderr)
        if failure.result and failure.result.get("network_attempted"):
            print(UNKNOWN_OUTCOME, file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, UnicodeError, RecursionError):
        print("Invalid, missing or oversized local request/configuration file.", file=sys.stderr)
        sys.exit(1)
