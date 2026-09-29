"""Small OpenAPI-backed client for the existing loopback HTTP server."""

import http.client
import json
import math
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SPEC_PATH = Path(__file__).resolve().parents[2] / "protocol/openapi.json"
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ApiClientError(Exception):
    """A local contract, transport, or response error."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ApiClientError("API server redirects are not allowed")


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    definition: dict

    @property
    def parameters(self):
        return self.definition.get("parameters", [])

    @property
    def accepts_body(self):
        return "requestBody" in self.definition

    @property
    def returns_binary(self):
        success = self.definition["responses"].get("200", {})
        return "application/octet-stream" in success.get("content", {})


@dataclass(frozen=True)
class ApiResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self):
        try:
            return json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiClientError("server returned invalid JSON") from error


class ApiContract:
    """Read operation IDs, routes and parameter rules from the versioned spec."""

    def __init__(self, spec_path=SPEC_PATH):
        with Path(spec_path).open(encoding="utf-8") as source:
            self.document = json.load(source)
        if not self.document.get("openapi", "").startswith("3.1."):
            raise ApiClientError("an OpenAPI 3.1 specification is required")
        self.operations = {}
        for path, item in self.document["paths"].items():
            for method, definition in item.items():
                if method not in {"get", "post", "put", "patch", "delete"}:
                    continue
                operation_id = definition["operationId"]
                if operation_id in self.operations:
                    raise ApiClientError(f"duplicate operationId: {operation_id}")
                self.operations[operation_id] = Operation(
                    operation_id, method.upper(), path, definition
                )

    def operation(self, operation_id):
        try:
            return self.operations[operation_id]
        except KeyError as error:
            raise ApiClientError(f"unknown operation: {operation_id}") from error


def local_base_url(value):
    """Reject remote targets and URL components outside the server root."""

    try:
        url = urllib.parse.urlsplit(value.strip())
        port = url.port
    except ValueError as error:
        raise ApiClientError("invalid API URL") from error
    if (url.scheme != "http" or url.hostname not in LOCAL_HOSTS or port is None
            or url.username is not None or url.password is not None
            or url.path not in {"", "/"} or url.query or url.fragment):
        raise ApiClientError("API URL must be an HTTP loopback server root with a port")
    host = f"[{url.hostname}]" if url.hostname == "::1" else url.hostname
    return f"http://{host}:{port}"


def _parameter_text(value):
    if value is None:
        raise ApiClientError("parameter values cannot be null")
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if "\r" in text or "\n" in text:
        raise ApiClientError("parameter values cannot contain line breaks")
    return text


class ApiClient:
    """Call one documented operation without changing server-side semantics."""

    def __init__(self, base_url, contract=None, timeout=30.0):
        self.base_url = local_base_url(base_url)
        self.contract = contract or ApiContract()
        if not math.isfinite(timeout) or timeout <= 0:
            raise ApiClientError("timeout must be a positive finite number")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RejectRedirects()
        )

    def call(self, operation_id, parameters=None, body=None):
        operation = self.contract.operation(operation_id)
        values = dict(parameters or {})
        definitions = {parameter["name"]: parameter for parameter in operation.parameters}
        unknown = set(values) - set(definitions)
        if unknown:
            raise ApiClientError(f"unknown parameter(s): {', '.join(sorted(unknown))}")
        missing = {name for name, definition in definitions.items()
                   if definition.get("required") and name not in values}
        if missing:
            raise ApiClientError(f"missing parameter(s): {', '.join(sorted(missing))}")

        path = operation.path
        query = []
        headers = {"Accept": "application/octet-stream" if operation.returns_binary
                   else "application/json"}
        for name, value in values.items():
            text = _parameter_text(value)
            location = definitions[name]["in"]
            if location == "path":
                if not text:
                    raise ApiClientError(f"path parameter {name} cannot be empty")
                path = path.replace("{" + name + "}", urllib.parse.quote(text, safe=""))
            elif location == "query":
                query.append((name, text))
            elif location == "header":
                headers[name] = text
            else:
                raise ApiClientError(f"unsupported parameter location: {location}")

        data = None
        if operation.accepts_body:
            if body is None:
                raise ApiClientError(f"{operation_id} requires a JSON body")
            if not isinstance(body, dict):
                raise ApiClientError("request body must be a JSON object")
            try:
                data = json.dumps(body, ensure_ascii=False, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise ApiClientError("request body is not valid JSON") from error
            maximum = operation.definition.get("x-max-body-bytes")
            if maximum is not None and len(data) > maximum:
                raise ApiClientError(f"request body exceeds {maximum} UTF-8 bytes")
            headers["Content-Type"] = "application/json"
        elif body is not None:
            raise ApiClientError(f"{operation_id} does not accept a body")

        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=operation.method)
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            raise ApiClientError(f"request failed: {error}") from error
        try:
            with response:
                return ApiResponse(response.status,
                                   {key.lower(): value for key, value in response.headers.items()},
                                   response.read())
        except (OSError, http.client.HTTPException) as error:
            raise ApiClientError(f"response failed: {error}") from error


def endpoint_file_url(path):
    """Read an explicitly selected server endpoint file, not a global default."""

    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ApiClientError(f"cannot read endpoint file: {error}") from error
    return local_base_url(value)
