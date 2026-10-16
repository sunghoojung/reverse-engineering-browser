/* Shared offline exports for UI and CLI. Captures stay inert data; no network or shell execution. */
const capturedExportFormats = (() => {
  const node = typeof module === 'object' && module?.exports && typeof require === 'function';
  const client = node ? require('./captured_client.js') : {capturedClientProject,capturedClientZip,capturedClientJSON};
  const traffic = node ? require('./traffic_view.js') : {trafficCaptureDocument};
  const byteLength = value => new TextEncoder().encode(value).length;
  const decodeBase64 = value => {
    let binary;
    try { binary = atob(value); } catch { throw new TypeError('Captured response has invalid base64.'); }
    if (btoa(binary) !== value) throw new TypeError('Captured response has invalid base64.');
    return Uint8Array.from(binary, character => character.charCodeAt(0));
  };
  const pythonTemplate = [
    "\"\"\"One reviewed request. Captured inputs are JSON data, never evaluated code.\"\"\"\n",
    "import json\n",
    "import math\n",
    "import os\n",
    "from pathlib import Path\n",
    "import re\n",
    "import sys\n",
    "from urllib.parse import urlsplit\n",
    "\n",
    "HTTP_CLIENT = \"__REB_PYTHON_CLIENT__\"\n",
    "HTTP_CLIENT_VERSION = \"__REB_PYTHON_VERSION__\"\n",
    "CONFIG_VERSION = \"reb-python-client-config-v1\"\n",
    "MAX_SAFE_INTEGER = 9007199254740991\n",
    "INTEGER = re.compile(r\"-?(0|[1-9][0-9]*)\\Z\")\n",
    "PARAMETER = re.compile(\n",
    "    r\"\\s*;\\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\\s*=\\s*\"\n",
    "    r\"\"\"(?:(?P<token>[!#$%&'*+.^_`|~0-9A-Za-z-]+)|\"(?P<quoted>(?:[^\"\\\\]|\\\\.)*)\")\\s*(?=;|$)\"\"\"\n",
    ")\n",
    "UNKNOWN_OUTCOME = (\n",
    "    \"The server may have processed this request; check its state before another \"\n",
    "    \"send. No automatic retry occurred.\"\n",
    ")\n",
    "\n",
    "\n",
    "class ClientError(Exception):\n",
    "    def __init__(self, code, message, result=None):\n",
    "        super().__init__(message)\n",
    "        self.code = code\n",
    "        self.result = result\n",
    "\n",
    "\n",
    "class _Number(str):\n",
    "    pass\n",
    "\n",
    "\n",
    "def parse_json(text, *, integers_only=False):\n",
    "    \"\"\"Bounded unique-key JSON with Unicode and original number-token checks.\"\"\"\n",
    "    if len(text.encode(\"utf-8\")) > 1048576:\n",
    "        raise ValueError(\"JSON exceeds 1 MiB.\")\n",
    "\n",
    "    def pairs(items):\n",
    "        result = {}\n",
    "        for key, value in items:\n",
    "            if key in result:\n",
    "                raise ValueError(\"Duplicate JSON key.\")\n",
    "            result[key] = value\n",
    "        return result\n",
    "\n",
    "    def constant(_token):\n",
    "        raise ValueError(\"Non-finite JSON number.\")\n",
    "\n",
    "    value = json.loads(text, object_pairs_hook=pairs, parse_int=_Number,\n",
    "                       parse_float=_Number, parse_constant=constant)\n",
    "    numbers = {}\n",
    "\n",
    "    def visit(item, depth=0, pointer=\"\"):\n",
    "        if depth > 64:\n",
    "            raise ValueError(\"JSON nesting exceeds 64.\")\n",
    "        if isinstance(item, _Number):\n",
    "            numbers[pointer] = str(item)\n",
    "            if integers_only and (not INTEGER.fullmatch(item) or\n",
    "                                  abs(int(item)) > MAX_SAFE_INTEGER):\n",
    "                raise ValueError(\"Request/config numbers require safe integer tokens.\")\n",
    "            number = int(item) if INTEGER.fullmatch(item) else float(item)\n",
    "            try:\n",
    "                if not math.isfinite(number):\n",
    "                    raise ValueError(\"Non-finite JSON number.\")\n",
    "            except OverflowError as error:\n",
    "                raise ValueError(\"Unrepresentable JSON number.\") from error\n",
    "            return number\n",
    "        if isinstance(item, str):\n",
    "            item.encode(\"utf-8\", errors=\"strict\")\n",
    "        elif isinstance(item, list):\n",
    "            return [visit(child, depth + 1, pointer + \"/\" + str(index))\n",
    "                    for index, child in enumerate(item)]\n",
    "        elif isinstance(item, dict):\n",
    "            for key in item:\n",
    "                key.encode(\"utf-8\", errors=\"strict\")\n",
    "            return {key: visit(child, depth + 1, pointer + \"/\" +\n",
    "                               key.replace(\"~\", \"~0\").replace(\"/\", \"~1\"))\n",
    "                    for key, child in item.items()}\n",
    "        return item\n",
    "\n",
    "    return visit(value), numbers\n",
    "\n",
    "\n",
    "def read_json(path, *, integers_only=False):\n",
    "    with Path(path).open(\"rb\") as source:\n",
    "        data = source.read(1048577)\n",
    "    if len(data) > 1048576:\n",
    "        raise ValueError(\"JSON exceeds 1 MiB.\")\n",
    "    return parse_json(data.decode(\"utf-8\", errors=\"strict\"),\n",
    "                      integers_only=integers_only)[0]\n",
    "\n",
    "\n",
    "def _object(value, allowed):\n",
    "    return isinstance(value, dict) and set(value).issubset(allowed)\n",
    "\n",
    "\n",
    "def _integer(value, low, high):\n",
    "    return type(value) is int and low <= value <= high\n",
    "\n",
    "\n",
    "def _default(value, fallback):\n",
    "    return fallback if value is None else value\n",
    "\n",
    "\n",
    "def _url(value):\n",
    "    if (not isinstance(value, str) or len(value) > 8192 or\n",
    "            not value.startswith((\"http://\", \"https://\")) or\n",
    "            any(ord(char) < 33 or ord(char) > 126 for char in value) or\n",
    "            any(char in value for char in \"\\\\#\")):\n",
    "        raise ValueError(\"A complete ASCII HTTP(S) URL without controls is required.\")\n",
    "    parsed = urlsplit(value)\n",
    "    if (not parsed.hostname or parsed.username is not None or\n",
    "            parsed.password is not None or \"%\" in parsed.netloc or\n",
    "            parsed.netloc.endswith(\":\")):\n",
    "        raise ValueError(\"URL credentials, escaped hosts and invalid ports are unsupported.\")\n",
    "    port = parsed.port\n",
    "    if port is not None and not 1 <= port <= 65535:\n",
    "        raise ValueError(\"Invalid URL port.\")\n",
    "    host = parsed.hostname.lower()\n",
    "    if \":\" in host:\n",
    "        host = \"[\" + host + \"]\"\n",
    "    if port is not None and (parsed.scheme, port) not in [(\"http\", 80), (\"https\", 443)]:\n",
    "        host += \":\" + str(port)\n",
    "    target = parsed.path or \"/\"\n",
    "    if \"?\" in value:\n",
    "        target += \"?\" + parsed.query\n",
    "    return parsed.scheme + \"://\" + host, target\n",
    "\n",
    "\n",
    "def request_issues(request):\n",
    "    issues = []\n",
    "    keys = {\"method\", \"url\", \"headers\", \"body\", \"timeout_ms\"}\n",
    "    if not _object(request, keys) or set(request) != keys:\n",
    "        return [\"A complete request object with known keys is required.\"]\n",
    "    method = request[\"method\"]\n",
    "    if (not isinstance(method, str) or\n",
    "            not re.fullmatch(r\"[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}\", method) or\n",
    "            method in [\"CONNECT\", \"TRACE\", \"TRACK\"]):\n",
    "        issues.append(\"Unsupported uppercase HTTP method.\")\n",
    "    try:\n",
    "        _url(request[\"url\"])\n",
    "    except (ValueError, TypeError):\n",
    "        issues.append(\"Python requires a complete ASCII HTTP(S) URL without credentials, fragment or controls.\")\n",
    "    forbidden = {\n",
    "        \"authorization\", \"proxy-authorization\", \"cookie\", \"cookie2\", \"set-cookie\",\n",
    "        \"host\", \"content-length\", \"connection\", \"transfer-encoding\", \"accept-charset\",\n",
    "        \"accept-encoding\", \"access-control-request-headers\", \"access-control-request-method\",\n",
    "        \"date\", \"dnt\", \"expect\", \"keep-alive\", \"origin\", \"referer\", \"te\", \"trailer\",\n",
    "        \"upgrade\", \"user-agent\", \"via\", \"content-encoding\",\n",
    "    }\n",
    "    headers = request[\"headers\"]\n",
    "    if not isinstance(headers, list) or len(headers) > 64:\n",
    "        issues.append(\"At most 64 complete header pairs are required.\")\n",
    "    else:\n",
    "        seen, total = set(), 0\n",
    "        for pair in headers:\n",
    "            if not isinstance(pair, list) or len(pair) != 2 or any(type(v) is not str for v in pair):\n",
    "                issues.append(\"Malformed header pair.\")\n",
    "                continue\n",
    "            name, value = pair\n",
    "            lower = name.lower()\n",
    "            total += len(name.encode(\"utf-8\")) + len(value.encode(\"utf-8\"))\n",
    "            if (not re.fullmatch(r\"[!#$%&'*+.^_`|~0-9A-Za-z-]+\", name) or len(name) > 128 or\n",
    "                    len(value) > 2048 or value.strip() != value or\n",
    "                    any(ord(char) < 32 or ord(char) > 126 for char in value)):\n",
    "                issues.append(\"Only bounded ASCII header values without surrounding whitespace or controls are supported.\")\n",
    "            if lower in seen:\n",
    "                issues.append(\"Duplicate header names are unsupported.\")\n",
    "            seen.add(lower)\n",
    "            if lower in forbidden or lower.startswith((\"sec-\", \"proxy-\")):\n",
    "                issues.append(\"Credential, transport, browser-controlled or encoded-body headers require manual reconstruction.\")\n",
    "            if lower in [\"x-http-method\", \"x-http-method-override\", \"x-method-override\"]:\n",
    "                if any(part.strip().upper() in [\"CONNECT\", \"TRACE\", \"TRACK\"] for part in value.split(\",\")):\n",
    "                    issues.append(\"Unsupported method override.\")\n",
    "            if lower == \"content-type\":\n",
    "                media = value.split(\";\", 1)[0].strip().lower()\n",
    "                if not re.fullmatch(r\"text/[a-z0-9.+-]+|application/(json|[a-z0-9.-]+\\+json|xml|[a-z0-9.-]+\\+xml|x-www-form-urlencoded|graphql|x-ndjson|ndjson)\", media):\n",
    "                    issues.append(\"Only recognized UTF-8 text media types are supported.\")\n",
    "                position, charset_seen = len(value.split(\";\", 1)[0]), False\n",
    "                while position < len(value):\n",
    "                    parameter = PARAMETER.match(value, position)\n",
    "                    if parameter is None:\n",
    "                        issues.append(\"Malformed Content-Type parameters are unsupported.\")\n",
    "                        break\n",
    "                    position = parameter.end()\n",
    "                    name = parameter[1].lower()\n",
    "                    if name == \"charset\":\n",
    "                        charset = parameter[\"token\"]\n",
    "                        if charset is None:\n",
    "                            charset = re.sub(r\"\\\\(.)\", r\"\\1\", parameter[\"quoted\"])\n",
    "                        if charset_seen or not re.fullmatch(r\"utf-?8\", charset, re.I):\n",
    "                            issues.append(\"Exactly one UTF-8 charset declaration is supported.\")\n",
    "                        charset_seen = True\n",
    "                    elif name.startswith(\"charset*\"):\n",
    "                        issues.append(\"Extended or segmented charset declarations are unsupported.\")\n",
    "        if total > 16384:\n",
    "            issues.append(\"Header text exceeds 16 KiB.\")\n",
    "    body = request[\"body\"]\n",
    "    if not isinstance(body, str) or len(body.encode(\"utf-8\")) > 65536:\n",
    "        issues.append(\"A complete UTF-8 text body of at most 64 KiB is required.\")\n",
    "    if method in [\"GET\", \"HEAD\"] and body != \"\":\n",
    "        issues.append(\"GET and HEAD bodies are unsupported.\")\n",
    "    if not _integer(request[\"timeout_ms\"], 100, 30000):\n",
    "        issues.append(\"Timeout must be 100–30000 ms.\")\n",
    "    return list(dict.fromkeys(issues))\n",
    "\n",
    "\n",
    "def configuration(config, request):\n",
    "    def fail(message):\n",
    "        raise ClientError(\"invalid_config\", message)\n",
    "\n",
    "    if not _object(config, {\"configVersion\", \"allowedOrigin\", \"request\", \"transport\", \"timeoutMs\",\n",
    "                            \"redirectPolicy\", \"cookiePolicy\", \"responseChecks\"}):\n",
    "        fail(\"Unknown or malformed client configuration.\")\n",
    "    if config.get(\"configVersion\") != CONFIG_VERSION:\n",
    "        fail(\"Use reb-python-client-config-v1; its per-operation timeouts are not an overall deadline.\")\n",
    "    transport = _default(config.get(\"transport\"), {\"mode\": \"standard\", \"browserProfile\": None})\n",
    "    if not _object(transport, {\"mode\", \"browserProfile\"}) or not isinstance(transport.get(\"mode\"), str):\n",
    "        fail(\"transport requires a supported mode.\")\n",
    "    if transport[\"mode\"] != \"standard\":\n",
    "        raise ClientError(\"unsupported_transport\", \"Python supports standard HTTP only. No profile fallback was attempted.\")\n",
    "    if transport.get(\"browserProfile\") is not None:\n",
    "        raise ClientError(\"unsupported_profile\", \"Standard HTTP does not accept a browser profile.\")\n",
    "    timeout = _default(config.get(\"timeoutMs\"), request.get(\"timeout_ms\") if isinstance(request, dict) else None)\n",
    "    if not _integer(timeout, 100, 30000):\n",
    "        fail(\"timeoutMs must be 100–30000 ms.\")\n",
    "    redirect = _default(config.get(\"redirectPolicy\"), \"manual\")\n",
    "    if redirect not in [\"manual\", \"error\"]:\n",
    "        fail(\"redirectPolicy must be manual or error; redirects are never followed.\")\n",
    "    if _default(config.get(\"cookiePolicy\"), \"omit\") != \"omit\":\n",
    "        fail(\"cookiePolicy must be omit.\")\n",
    "    checks = _default(config.get(\"responseChecks\"), {})\n",
    "    if not _object(checks, {\"statuses\", \"contentType\", \"jsonFields\"}):\n",
    "        fail(\"Malformed responseChecks.\")\n",
    "    statuses = _default(checks.get(\"statuses\"), [])\n",
    "    media = checks.get(\"contentType\")\n",
    "    fields = _default(checks.get(\"jsonFields\"), [])\n",
    "    if (not isinstance(statuses, list) or len(statuses) > 32 or\n",
    "            any(not _integer(status, 100, 599) for status in statuses) or len(set(statuses)) != len(statuses)):\n",
    "        fail(\"statuses must be at most 32 distinct HTTP status integers.\")\n",
    "    if media is not None and (not isinstance(media, str) or len(media) > 128 or\n",
    "                              not re.fullmatch(r\"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\", media)):\n",
    "        fail(\"contentType must be a lowercase media type without parameters.\")\n",
    "    if not isinstance(fields, list) or len(fields) > 32:\n",
    "        fail(\"At most 32 JSON field checks are supported.\")\n",
    "    for field in fields:\n",
    "        if not _object(field, {\"pointer\", \"type\", \"equals\"}):\n",
    "            fail(\"Malformed JSON field check.\")\n",
    "        pointer, kind = field.get(\"pointer\"), field.get(\"type\")\n",
    "        if (not isinstance(pointer, str) or len(pointer.encode(\"utf-8\")) > 1024 or\n",
    "                (pointer != \"\" and not pointer.startswith(\"/\")) or\n",
    "                re.search(r\"~(?![01])\", pointer) or len(pointer.split(\"/\")) > 33):\n",
    "            fail(\"Each JSON field requires a bounded RFC 6901 pointer.\")\n",
    "        if kind not in [\"null\", \"boolean\", \"number\", \"string\", \"array\", \"object\"]:\n",
    "            fail(\"Each JSON field requires a supported type.\")\n",
    "        if \"equals\" in field:\n",
    "            expected = field[\"equals\"]\n",
    "            valid = (kind == \"null\" and expected is None or\n",
    "                     kind == \"boolean\" and type(expected) is bool or\n",
    "                     kind == \"string\" and type(expected) is str and len(expected.encode(\"utf-8\")) <= 2048 or\n",
    "                     kind == \"number\" and _integer(expected, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER))\n",
    "            if not valid:\n",
    "                fail(\"equals requires a matching scalar type or safe integer.\")\n",
    "    return {\"transport\": transport, \"timeoutMs\": timeout, \"timeoutScope\": \"per-operation\",\n",
    "            \"redirectPolicy\": redirect, \"cookiePolicy\": \"omit\",\n",
    "            \"responseChecks\": {\"statuses\": statuses, \"contentType\": media, \"jsonFields\": fields}}\n",
    "\n",
    "\n",
    "def validate_response(result, policy):\n",
    "    def fail(code, message):\n",
    "        raise ClientError(code, message, result)\n",
    "\n",
    "    checks = policy[\"responseChecks\"]\n",
    "    configured = bool(checks[\"statuses\"] or checks[\"contentType\"] or checks[\"jsonFields\"])\n",
    "    result[\"validation\"] = {\"configured\": configured, \"passed\": False}\n",
    "    if policy[\"redirectPolicy\"] == \"error\" and 300 <= result[\"status\"] <= 399:\n",
    "        fail(\"redirect_refused\", \"Redirect refused; no redirect was followed.\")\n",
    "    if checks[\"statuses\"] and result[\"status\"] not in checks[\"statuses\"]:\n",
    "        fail(\"response_status\", \"Response status does not match the accepted statuses.\")\n",
    "    media = [value.split(\";\", 1)[0].strip().lower() for name, value in result[\"headers\"] if name.lower() == \"content-type\"]\n",
    "    if checks[\"contentType\"] and (len(media) != 1 or media[0] != checks[\"contentType\"]):\n",
    "        fail(\"response_content_type\", \"Response Content-Type does not match.\")\n",
    "    if configured and result[\"body_truncated\"]:\n",
    "        fail(\"response_truncated\", \"An incomplete response cannot pass response checks.\")\n",
    "    if checks[\"jsonFields\"]:\n",
    "        try:\n",
    "            if result[\"body_invalid_utf8\"]:\n",
    "                raise ValueError()\n",
    "            body, numbers = parse_json(result[\"body\"])\n",
    "        except (ValueError, UnicodeError, RecursionError):\n",
    "            fail(\"response_json\", \"Response is not complete valid unique-key JSON.\")\n",
    "        for field in checks[\"jsonFields\"]:\n",
    "            value = body\n",
    "            for part in ([] if field[\"pointer\"] == \"\" else field[\"pointer\"].split(\"/\")[1:]):\n",
    "                part = part.replace(\"~1\", \"/\").replace(\"~0\", \"~\")\n",
    "                if isinstance(value, list) and re.fullmatch(r\"0|[1-9][0-9]*\", part) and len(part) <= 16 and int(part) < len(value):\n",
    "                    value = value[int(part)]\n",
    "                elif isinstance(value, dict) and part in value:\n",
    "                    value = value[part]\n",
    "                else:\n",
    "                    fail(\"response_field_missing\", \"A configured JSON pointer is absent.\")\n",
    "            kind = {type(None): \"null\", bool: \"boolean\", int: \"number\", float: \"number\",\n",
    "                    str: \"string\", list: \"array\", dict: \"object\"}.get(type(value))\n",
    "            if kind != field[\"type\"]:\n",
    "                fail(\"response_field_type\", \"A configured JSON field has the wrong type.\")\n",
    "            if \"equals\" in field:\n",
    "                if kind == \"number\" and (not INTEGER.fullmatch(numbers.get(field[\"pointer\"], \"\")) or value != field[\"equals\"]):\n",
    "                    fail(\"response_field_value\", \"Numeric equals requires an exact integer JSON token.\")\n",
    "                if value != field[\"equals\"]:\n",
    "                    fail(\"response_field_value\", \"A configured JSON field has an unexpected value.\")\n",
    "    result[\"validation\"][\"passed\"] = configured\n",
    "    return result\n",
    "\n",
    "\n",
    "def _snapshot(result, data, truncated):\n",
    "    result[\"body_truncated\"] = truncated\n",
    "    try:\n",
    "        result[\"body\"] = bytes(data).decode(\"utf-8\", errors=\"strict\")\n",
    "        result[\"body_invalid_utf8\"] = False\n",
    "    except UnicodeDecodeError:\n",
    "        result[\"body\"] = bytes(data).decode(\"utf-8\", errors=\"replace\")\n",
    "        result[\"body_invalid_utf8\"] = True\n",
    "\n",
    "\n",
    "def _consume(result, status, headers, chunks):\n",
    "    result.update(status=status, network_requests=1, headers=[], redirect_followed=False,\n",
    "                  body=\"\", body_truncated=True, body_invalid_utf8=False)\n",
    "    size = 0\n",
    "    for name, value in headers:\n",
    "        size += len(name.encode(\"utf-8\")) + len(value.encode(\"utf-8\"))\n",
    "        if len(result[\"headers\"]) >= 128 or size > 65536:\n",
    "            result[\"headers_truncated\"] = True\n",
    "            raise ClientError(\"response_read\", \"Response headers exceed their retained limit.\", result)\n",
    "        result[\"headers\"].append([name, value])\n",
    "    data = bytearray()\n",
    "    _snapshot(result, data, False)\n",
    "    for chunk in chunks:\n",
    "        remaining = 65536 - len(data)\n",
    "        data.extend(chunk[:remaining])\n",
    "        _snapshot(result, data, len(chunk) > remaining)\n",
    "        if result[\"body_truncated\"]:\n",
    "            break\n",
    "\n",
    "\n",
    "def _perform(request, policy, result):\n",
    "    if HTTP_CLIENT not in [\"requests\", \"httpx\"]:\n",
    "        raise ClientError(\"unsupported_transport\", \"Unsupported Python HTTP client.\")\n",
    "    if os.environ.get(\"SSLKEYLOGFILE\"):\n",
    "        raise ClientError(\"unsupported_environment\", \"Disable TLS key logging before using this credential-omitting client.\")\n",
    "    seconds = policy[\"timeoutMs\"] / 1000\n",
    "    payload = request[\"body\"].encode(\"utf-8\")\n",
    "    expected_target = _url(request[\"url\"])[1]\n",
    "    if HTTP_CLIENT == \"requests\":\n",
    "        import requests\n",
    "        if getattr(requests, \"__version__\", None) != HTTP_CLIENT_VERSION:\n",
    "            raise ImportError(\"Use the reviewed provider pin.\")\n",
    "        with requests.Session() as session:\n",
    "            session.trust_env = False\n",
    "            session.headers.clear()\n",
    "            adapter = requests.adapters.HTTPAdapter(max_retries=0)\n",
    "            session.mount(\"http://\", adapter)\n",
    "            session.mount(\"https://\", adapter)\n",
    "            prepared = session.prepare_request(requests.Request(request[\"method\"], request[\"url\"],\n",
    "                headers={\"Accept-Encoding\": \"identity\", **dict(request[\"headers\"])}, data=payload))\n",
    "            if _url(prepared.url)[1] != expected_target:\n",
    "                raise ClientError(\"invalid_input\", \"Requests would normalize the captured target; supply a deliberately reviewed URL.\")\n",
    "            # Direct adapter.send avoids Session's hidden redirect-response drain\n",
    "            # even when allow_redirects=False, retaining a bounded streamed body.\n",
    "            result[\"network_attempted\"] = True\n",
    "            with adapter.send(prepared, stream=True, timeout=(seconds, seconds), verify=True, proxies={}) as response:\n",
    "                _consume(result, response.status_code, response.raw.headers.iteritems(),\n",
    "                         response.raw.stream(8192, decode_content=False))\n",
    "    else:\n",
    "        import httpx\n",
    "        if getattr(httpx, \"__version__\", None) != HTTP_CLIENT_VERSION:\n",
    "            raise ImportError(\"Use the reviewed provider pin.\")\n",
    "        transport = httpx.HTTPTransport(verify=True, trust_env=False, retries=0)\n",
    "        with httpx.Client(transport=transport, trust_env=False, follow_redirects=False,\n",
    "                          timeout=seconds, headers={\"Accept-Encoding\": \"identity\"}) as session:\n",
    "            prepared = session.build_request(request[\"method\"], request[\"url\"],\n",
    "                headers=dict(request[\"headers\"]), content=payload)\n",
    "            if prepared.url.raw_path.decode(\"ascii\") != expected_target:\n",
    "                raise ClientError(\"invalid_input\", \"HTTPX would normalize the captured target; supply a deliberately reviewed URL.\")\n",
    "            result[\"network_attempted\"] = True\n",
    "            response = session.send(prepared, stream=True, follow_redirects=False)\n",
    "            try:\n",
    "                _consume(result, response.status_code,\n",
    "                         ((key.decode(\"latin-1\"), value.decode(\"latin-1\")) for key, value in response.headers.raw),\n",
    "                         response.iter_raw())\n",
    "            finally:\n",
    "                response.close()\n",
    "\n",
    "\n",
    "def send_request(input_request, *, config=None, send=False, provenance=None):\n",
    "    config = {} if config is None else config\n",
    "    provenance = {} if provenance is None else provenance\n",
    "    request = _default(config.get(\"request\"), input_request) if isinstance(config, dict) else input_request\n",
    "    try:\n",
    "        problems = request_issues(request)\n",
    "    except (ValueError, TypeError, UnicodeError, OverflowError):\n",
    "        problems = [\"Request contains invalid text or values.\"]\n",
    "    policy, config_error = None, None\n",
    "    try:\n",
    "        policy = configuration(config, request)\n",
    "    except ClientError as error:\n",
    "        config_error = error\n",
    "        problems.append(str(error))\n",
    "    except (ValueError, TypeError, UnicodeError, OverflowError):\n",
    "        config_error = ClientError(\"invalid_config\", \"Configuration contains invalid text or values.\")\n",
    "        problems.append(str(config_error))\n",
    "    if (not isinstance(config, dict) or config.get(\"request\") is None) and (\n",
    "            not isinstance(provenance, dict) or provenance.get(\"format\") != \"reb-client-project-v1\" or\n",
    "            provenance.get(\"mode\") != \"raw\" or provenance.get(\"problems\")):\n",
    "        problems.append(\"Provide a complete reviewed config.request; exported evidence is redacted or unsupported.\")\n",
    "    if send is not True:\n",
    "        return {\"dry_run\": True, \"network_requests\": 0, \"ready\": not problems,\n",
    "                \"problems\": problems, \"method\": request.get(\"method\") if isinstance(request, dict) else None,\n",
    "                \"policy\": policy, \"instruction\": \"Review evidence and Python configuration before --send.\"}\n",
    "    if config_error:\n",
    "        raise config_error\n",
    "    if problems:\n",
    "        raise ClientError(\"invalid_input\", \" \".join(problems))\n",
    "    if config.get(\"allowedOrigin\") != _url(request[\"url\"])[0]:\n",
    "        raise ClientError(\"wrong_origin\", \"allowedOrigin must exactly match the reviewed origin.\")\n",
    "    result = {\"network_attempted\": False, \"network_requests\": 0, \"url\": request[\"url\"],\n",
    "              \"instruction\": UNKNOWN_OUTCOME, \"http_client\": HTTP_CLIENT,\n",
    "              \"timeout_scope\": \"per-operation\"}\n",
    "    try:\n",
    "        _perform(request, policy, result)\n",
    "        return validate_response(result, policy)\n",
    "    except ClientError:\n",
    "        raise\n",
    "    except ImportError as error:\n",
    "        raise ClientError(\"missing_dependency\", \"Install the reviewed requirements.txt before sending.\") from error\n",
    "    except Exception as error:\n",
    "        if result[\"network_attempted\"] and not result.get(\"status\"):\n",
    "            result[\"network_requests\"] = None\n",
    "        if result.get(\"status\"):\n",
    "            result[\"body_truncated\"] = True\n",
    "        # Exception names are classified, never printed with URLs or raw values.\n",
    "        timeout = \"timeout\" in type(error).__name__.lower()\n",
    "        raise ClientError(\"timeout\" if timeout else \"response_read\" if result.get(\"status\") else \"network\",\n",
    "                          \"A transport operation timed out.\" if timeout else \"Transport failed; the server outcome may be unknown.\", result) from error\n",
    "\n",
    "\n",
    "def main():\n",
    "    if sys.argv[1:] not in [[], [\"--send\"]]:\n",
    "        raise ValueError(\"Usage: python client.py [--send]\")\n",
    "    root = Path(__file__).resolve().parent\n",
    "    request = read_json(root / \"requests/request-001.json\", integers_only=True)\n",
    "    provenance = read_json(root / \"provenance.json\")\n",
    "    try:\n",
    "        config = read_json(root / \"config.json\", integers_only=True)\n",
    "    except FileNotFoundError:\n",
    "        config = {}\n",
    "    print(json.dumps(send_request(request, config=config, provenance=provenance,\n",
    "                                  send=sys.argv[1:] == [\"--send\"]), ensure_ascii=False))\n",
    "\n",
    "\n",
    "if __name__ == \"__main__\":\n",
    "    try:\n",
    "        main()\n",
    "    except ClientError as failure:\n",
    "        print(failure.code + \": \" + str(failure), file=sys.stderr)\n",
    "        if failure.result and failure.result.get(\"network_attempted\"):\n",
    "            print(UNKNOWN_OUTCOME, file=sys.stderr)\n",
    "        sys.exit(1)\n",
    "    except (ValueError, OSError, UnicodeError, RecursionError):\n",
    "        print(\"Invalid, missing or oversized local request/configuration file.\", file=sys.stderr)\n",
    "        sys.exit(1)\n"
  ].join('');
function pythonProject(source, mode, httpClient) {
  const versions = {requests:'2.34.2',httpx:'0.28.1'};
  if (!Object.hasOwn(versions,httpClient)) throw new TypeError('Choose requests or httpx.');
  const project = client.capturedClientProject(source,mode);
  const prefix = 'reb-client-project/';
  const paths = ['provenance.json','requests/request-001.json','config.example.json','.gitignore','evidence/capture.json','evidence/repeater-run.json'];
  const files = project.files.filter(file=>paths.includes(file.path.slice(prefix.length)));
  const add = (path,text) => files.push({path:prefix+path,text});
  files.find(file=>file.path===prefix+'.gitignore').text+='__pycache__/\n.venv/\n';
  const config = files.find(file=>file.path===prefix+'config.example.json');
  const settings = JSON.parse(config.text);settings.configVersion='reb-python-client-config-v1';
  config.text=JSON.stringify(settings,null,2)+'\n';
  // Keep the shared evidence/privacy warnings, but describe this archive's transport.
  project.provenance.limitations=project.provenance.limitations.map(value =>
    value.startsWith('Default Go uses ') ? 'Python uses standard '+httpClient+' with certificate verification and per-operation timeouts, not an overall deadline. No browser profile, ambient proxy, cookie carryover or automatic decompression.' :
    value.startsWith('Both clients omit ') ? 'This Python client omits browser credentials and stops redirects; optional response checks must be configured explicitly.' : value);
  project.provenance.client_capabilities={language:'python',http_client:httpClient,dependency_version:versions[httpClient],
    timeout_scope:'per-operation',overall_deadline:false,redirect_following:false,ambient_proxy:false,cookies:'omit',browser_profile:false};
  files.find(file=>file.path===prefix+'provenance.json').text=JSON.stringify(project.provenance,null,2)+'\n';
  const template = pythonTemplate;
  add('client.py',template.replace('__REB_PYTHON_CLIENT__',httpClient).replace('__REB_PYTHON_VERSION__',versions[httpClient]));
  add('requirements.txt',httpClient+'=='+versions[httpClient]+'\n');
  add('README.md',`# One observed Python request

This offline project uses ${httpClient} ${versions[httpClient]} with Python 3.11+. Captured inputs are JSON data, never executable source. The export is one observed operation, not an inferred service API or verified replay.

## Review and run

Review requirements.txt, then install it explicitly into your own virtual environment with python -m pip install -r requirements.txt. Export never installs dependencies. The client requires this exact provider version before sending. The direct dependency is pinned; its transitive dependency resolution is not a complete lockfile. Follow your environment's dependency review policy.

Run python client.py for a dry run with zero target requests; dry runs need only the standard library, not the provider dependency. Copy config.example.json to config.json, review the request/evidence and set allowedOrigin to the exact authorized origin. Only python client.py --send performs one deliberate request. No automatic retry occurs. Both clients verify TLS certificates, refuse ambient TLS key logging, ignore ambient proxy/netrc configuration, omit original browser cookies, and do not follow redirects or automatically decompress response bodies.

## Python timeout contract

configVersion is reb-python-client-config-v1. timeoutMs (or request.timeout_ms when null) is 100–30000 ms per blocking operation. Requests has separate connect/read timeouts; HTTPX also applies write/pool timeouts. This is NOT an overall deadline: DNS resolution, multiple address attempts, and a response that keeps producing bytes can take longer. The provenance records this capability. Existing Go/JavaScript reb-client-config-v1 files are rejected instead of silently weakening their whole-request deadline.

The remaining request, origin, redirectPolicy, cookiePolicy, standard transport and opt-in responseChecks fields have the existing meanings. An unsupported browser profile fails before sending. Redacted or unsupported captures require a complete reviewed config.request. Missing, null, wrong-type and unexpected JSON field values remain distinct. Numeric equality requires the original exact integer JSON token; duplicate keys and invalid Unicode fail.

## Bounds and limitations

Inputs/configuration are at most 1 MiB and JSON depth 64. Request text is at most 64 KiB; headers at most 64 pairs/16 KiB. Python requires ASCII URLs and header values. Preparation that changes the captured URL path/query is rejected; supply a deliberately reviewed URL rather than assuming equivalence. Encoded query spellings may therefore require manual reconstruction, especially with Requests. Multipart, binary, truncated and credential-bearing inputs remain evidence, not runnable defaults. Responses retain at most 64 KiB body and 128 headers/64 KiB header text. Configured checks cannot pass truncated responses.

Header casing/order, automatic headers, TLS, compression, CORS and browser state differ. Neither provider implements the optional Go browser-profile adapter or browser fingerprint parity. Error reports preserve an unknown server outcome after an attempted send; inspect state before another deliberate request. There is no response persistence, streaming API or login/credential acquisition.

Export mode: ${mode}. Raw evidence may contain credentials or personal data. The explicit best-effort redacted copy can still contain sensitive names, paths and identifiers. Review before sharing. .gitignore is not a security boundary. Source provenance describes a saved snapshot and does not attest to authenticity or current retention.
`);
  return {files,provenance:project.provenance,bytes:client.capturedClientZip(files)};
}

function validateTimingEvidence(value, invalid = () => { throw new TypeError('HAR export unsupported: invalid source timing contract.'); }) {
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
  const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  const clocks = ['request_monotonic_seconds','request_wall_seconds','response_monotonic_seconds','completion_monotonic_seconds'];
  const flags = ['response_observed','completion_observed','duplicate_response','duplicate_completion','response_after_completion'];
  if (!exact(value,['format',...clocks,...flags,'resource_timing','response_source','completion_source']) || value.format !== 'reb-network-timing-v1' ||
      !flags.every(key => typeof value[key] === 'boolean') || !['none','redirectResponse','responseReceived'].includes(value.response_source) ||
      !['none','redirectRequest','loadingFailed','loadingFinished'].includes(value.completion_source)) invalid();
  const measurement = (item,offset = false) => exact(item,['state','value']) && item.state === 'available' && finite(item.value) && item.value <= 8640000000000 ||
    exact(item,['state']) && (offset ? ['missing','invalid','unavailable'] : ['missing','invalid']).includes(item.state);
  if (!clocks.every(key => measurement(value[key]))) invalid();
  const resource = value.resource_timing;
  if (exact(resource,['state']) && ['missing','invalid'].includes(resource.state)) return;
  const fields = ['requestTime','proxyStart','proxyEnd','dnsStart','dnsEnd','connectStart','connectEnd','sslStart','sslEnd','sendStart','sendEnd','receiveHeadersStart','receiveHeadersEnd','workerStart'];
  if (!exact(resource,['state','fields']) || resource.state !== 'available' || !exact(resource.fields,fields) ||
      !fields.every(key => measurement(resource.fields[key],key !== 'requestTime'))) invalid();
}

const har = (() => {
// Offline HAR 1.2 projection. Never replay, normalize source evidence or invent phases.
const fail = reason => { throw new Error('HAR export unsupported: '+reason); };
const measured = item => {
  if (item?.state !== 'available' || typeof item.value !== 'number' || !Number.isFinite(item.value) || item.value < 0) fail('required source timing is unavailable.');
  return item.value;
};
function timing(record) {
  const t = record.timing_evidence;
  validateTimingEvidence(t);
  if (t?.format !== 'reb-network-timing-v1' || !t.response_observed || !t.completion_observed || t.duplicate_response || t.duplicate_completion || t.response_after_completion ||
      t.response_source !== 'responseReceived' || t.completion_source !== 'loadingFinished' || t.resource_timing.state !== 'available') fail('complete unambiguous source lifecycle timing is required.');
  const start = measured(t.request_monotonic_seconds), wall = measured(t.request_wall_seconds), response = measured(t.response_monotonic_seconds), finish = measured(t.completion_monotonic_seconds);
  const f = t.resource_timing.fields, base = measured(f.requestTime);
  if (record.started_monotonic_ms !== start*1000 || base < start || wall > 253402300799.999) fail('source clocks are incompatible with the retained request or ISO date range.');
  const pair = (first,last) => {
    if (f[first]?.state === 'unavailable' && f[last]?.state === 'unavailable') return null;
    const a=measured(f[first]), b=measured(f[last]);
    if (b<a) fail('source timing interval is reversed.');
    return [a,b];
  };
  const dns=pair('dnsStart','dnsEnd'), connect=pair('connectStart','connectEnd'), ssl=pair('sslStart','sslEnd');
  if (f.workerStart?.state !== 'unavailable' || f.proxyStart?.state !== 'unavailable' || f.proxyEnd?.state !== 'unavailable') fail('worker/proxy timing cannot be represented by this exporter.');
  const sendStart=measured(f.sendStart), sendEnd=measured(f.sendEnd), headerStart=measured(f.receiveHeadersStart), headerEnd=measured(f.receiveHeadersEnd);
  const finishOffset=(finish-base)*1000, responseOffset=(response-base)*1000;
  if (sendEnd<sendStart || headerStart<sendEnd || headerEnd<headerStart || responseOffset<headerEnd || finishOffset<responseOffset ||
      dns && dns[1]>sendStart || connect && connect[1]>sendStart || dns && connect && dns[1]>connect[0] ||
      ssl && (!connect || ssl[0]<connect[0] || ssl[1]>connect[1])) fail('source phase order is inconsistent.');
  const length = interval => interval ? interval[1]-interval[0] : -1;
  const blocked=(base-start)*1000+sendStart-Math.max(0,length(dns))-Math.max(0,length(connect));
  if (blocked<0) fail('source setup phases overlap.');
  const timings={blocked,dns:length(dns),connect:length(connect),send:sendEnd-sendStart,wait:headerStart-sendEnd,receive:finishOffset-headerStart,ssl:length(ssl),
    comment:'Derived from CDP monotonic clocks. Blocked is pre-send residual excluding disjoint DNS/connection intervals; TLS overlaps connect. Receive starts at the first response header byte.'};
  const time=['blocked','dns','connect','send','wait','receive'].reduce((sum,key)=>sum+Math.max(0,timings[key]),0);
  return {startedDateTime:new Date(wall*1000).toISOString(),time,timings};
}
function body(value) {
  if (value.truncated || !['available','empty'].includes(value.state) || value.text && value.base64 || value.state==='empty' && (value.text || value.base64)) fail('complete unambiguous retained bodies are required.');
  if (value.base64) {
    let bytes;
    try { bytes=decodeBase64(value.base64); } catch { fail('response base64 is not canonical.'); }
    return {size:bytes.length,text:value.base64,encoding:'base64'};
  }
  return {size:byteLength(value.text),text:value.text};
}
function query(url) {
  const start=url.indexOf('?');
  if(start<0 || start===url.length-1)return [];
  try {return url.slice(start+1).split('&').map(pair=>{
    const index=pair.indexOf('='),name=index<0?pair:pair.slice(0,index),value=index<0?'':pair.slice(index+1);
    return {name:decodeURIComponent(name.replace(/\+/g,' ')),value:decodeURIComponent(value.replace(/\+/g,' '))};
  });} catch {fail('query bytes cannot be losslessly represented as Unicode HAR parameters.');}
}
function harProject(source,mode='raw') {
  if (!['raw','redacted_copy'].includes(mode)) fail('unknown copy policy.');
  const raw=source.evidence.record;
  if(raw.state!=='complete' || raw.from_disk_cache || raw.from_service_worker || raw.url_truncated || raw.method_truncated ||
      raw.request.headers_truncated || raw.response.headers_truncated || !Number.isInteger(raw.status) || raw.status<100 || raw.status>599) fail('incomplete, cached, failed or truncated source data.');
  if (!/^https?:\/\//i.test(raw.url) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(raw.method)) fail('unsupported HTTP request.');
  const versions={'HTTP/1.0':'HTTP/1.0','HTTP/1.1':'HTTP/1.1','h2':'HTTP/2.0','h3':'HTTP/3.0'};
  if(!versions[raw.protocol]) fail('unknown HTTP protocol.');
  const phase=timing(raw),requestBody=body(raw.request.body),responseBody=body(raw.response.body);
  if(requestBody.encoding) fail('binary request postData cannot be represented by HAR 1.2 text.');
  if(!responseBody.encoding && responseBody.size>0) {
    const contentType=raw.response.headers.filter(([name])=>name.toLowerCase()==='content-type');
    if(contentType.length!==1) fail('text response requires an unambiguous UTF-8 media type.');
    const type=contentType[0][1];
    const parameter = /\s*;\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:([!#$%&'*+.^_`|~0-9A-Za-z-]+)|"((?:[^"\\]|\\.)*)")\s*(?=;|$)/y;
    let position=type.split(';',1)[0].length,charsetSeen=false;
    while(position<type.length) {
      parameter.lastIndex=position;const match=parameter.exec(type);
      if(!match) fail('malformed response Content-Type parameters.');
      position=parameter.lastIndex;const name=match[1].toLowerCase();
      if(name==='charset') {
        const charset=match[2]??match[3].replace(/\\(.)/g,'$1');
        if(charsetSeen || !/^utf-?8$/i.test(charset)) fail('original text byte size is unknown for this charset.');
        charsetSeen=true;
      } else if(name.startsWith('charset*')) fail('extended charset declarations are unsupported.');
    }
    if(!charsetSeen && !/^application\/(?:json|[a-z0-9.-]+\+json)\s*$/i.test(type.split(';',1)[0])) fail('original text byte size is unknown for this charset.');
  }
  const record=mode==='raw'?raw:traffic.trafficCaptureDocument({captureRecord:raw},mode).record;
  const url=record.url.split('#',1)[0], headers=side=>record[side].headers.map(([name,value])=>({name,value}));
  const mime=side=>mode==='redacted_copy'?'application/octet-stream':raw[side].headers.find(([name])=>name.toLowerCase()==='content-type')?.[1] || raw[side].body.mime || 'application/octet-stream';
  // CDP text has already been transcoded; its UTF-8 length is not original entity size.
  const request={method:record.method,url,httpVersion:versions[raw.protocol],cookies:[],headers:headers('request'),queryString:query(url),headersSize:-1,bodySize:raw.request.body.state==='empty'?0:-1,
    _cookiesParsed:false,_bodySizeKnown:raw.request.body.state==='empty'};
  if(raw.request.body.state!=='empty') request.postData={mimeType:mime('request'),text:mode==='raw'?requestBody.text:'',...(mode==='redacted_copy'?{_redacted:true}:{})};
  const content={size:responseBody.size,mimeType:mime('response'),...(mode==='raw'?responseBody:{_redacted:true}),_sizeBasis:responseBody.encoding?'retained-decoded-bytes':'retained-UTF-8-text'};
  const location=record.response.headers.filter(([name])=>name.toLowerCase()==='location');
  if(location.length>1) fail('ambiguous redirect header.');
  const response={status:record.status,statusText:record.status_text,httpVersion:versions[raw.protocol],cookies:[],headers:headers('response'),content,
    redirectURL:mode==='raw'?(location[0]?.[1]??''):'',headersSize:-1,bodySize:-1,_cookiesParsed:false};
  const entry={...phase,request,response,cache:{},_reb:{format:'reb-har-entry-v1',mode,source_identity:source.identity,
    coverage:source.evidence.coverage,timing_evidence:raw.timing_evidence,
    limitations:['CDP headers are normalized and may omit wire fields; cookie objects are not parsed.','Wire header/body sizes and cache details are unknown.','Text body size describes retained UTF-8, not original entity octets.','ISO timestamp has millisecond precision; source wall seconds are retained.']}};
  const document={log:{version:'1.2',creator:{name:'Reverse Engineering Browser',version:'reb-har-v1'},entries:[entry]}};
  const bytes=new TextEncoder().encode(JSON.stringify(document,null,2)+'\n');
  if(bytes.length>2097152) fail('output exceeds 2 MiB.');
  return {document,bytes};
}

return {harProject};
})();
const graphql = (() => {
// Bounded structural SDL projection, never a GraphQL query executor.
const fail=()=>{throw new Error('Unsupported or incomplete GraphQL introspection. Supply a complete bounded schema with valid names, references and literal defaults.');};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const name=value=>typeof value==='string'&&value.length<=256&&/^[_A-Za-z][_0-9A-Za-z]*$/.test(value)&&!value.startsWith('__')?value:fail();
const list=(value,max=4096)=>Array.isArray(value)&&value.length<=max?value:fail();
const unique=(items,key='name')=>{const seen=new Set();for(const item of items){const n=name(item[key]);if(seen.has(n))fail();seen.add(n);}return items;};
const description=(value,indent='')=>value===null||value===undefined?'':typeof value==='string'&&byteLength(value)<=16384?indent+JSON.stringify(value)+'\n':fail();
const kinds=new Set(['SCALAR','OBJECT','INTERFACE','UNION','ENUM','INPUT_OBJECT']);
const builtinScalars=new Set(['Int','Float','String','Boolean','ID']);
const builtinDirectives=new Set(['skip','include','deprecated','specifiedBy','oneOf']);
const locations=new Set(['QUERY','MUTATION','SUBSCRIPTION','FIELD','FRAGMENT_DEFINITION','FRAGMENT_SPREAD','INLINE_FRAGMENT','VARIABLE_DEFINITION','SCHEMA','SCALAR','OBJECT','FIELD_DEFINITION','ARGUMENT_DEFINITION','INTERFACE','UNION','ENUM','ENUM_VALUE','INPUT_OBJECT','INPUT_FIELD_DEFINITION']);

// Validate one GraphQL constant literal before emitting it; arbitrary SDL is refused.
function constantLiteral(source) {
  if(typeof source!=='string'||byteLength(source)>16384)fail();
  let position=0,nodes=0;
  const space=()=>{while(position<source.length&&/[\t\n\r ,\uFEFF]/u.test(source[position]))position++;};
  function value(depth=0) {
    if(depth>32||++nodes>4096)fail();space();const start=position,c=source[position];
    if(c==='['||c==='{') {
      position++;space();const end=c==='['?']':'}',seen=new Set();
      while(source[position]!==end) {
        if(position>=source.length)fail();
        if(c==='{') {const match=/^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(position));if(!match||seen.has(match[0]))fail();seen.add(match[0]);position+=match[0].length;space();if(source[position++]!==':')fail();}
        value(depth+1);space();
      }
      position++;return;
    }
    if(c==='"') {
      if(source.startsWith('"""',position)) {
        position+=3;
        while(position<source.length) {
          if(source.startsWith('\\"""',position)){position+=4;continue;}
          if(source.startsWith('"""',position)){position+=3;return;}
          if(source.charCodeAt(position)<32&&!['\t','\n','\r'].includes(source[position]))fail();position++;
        }
        fail();
      }
      position++;let escaped=false;
      while(position<source.length) {const ch=source[position++];if(!escaped&&ch==='"'){try{if(!JSON.parse(source.slice(start,position)).isWellFormed())fail();}catch{fail();}return;}if(!escaped&&ch==='\\')escaped=true;else escaped=false;}
      fail();
    }
    const token=/^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[_A-Za-z][_0-9A-Za-z]*)/.exec(source.slice(position));
    if(!token)fail();position+=token[0].length;
    if(position<source.length&&!/[\t\n\r ,\]}\uFEFF]/u.test(source[position]))fail();
  }
  value();space();if(position!==source.length)fail();return source.trim();
}

function introspectionSDL(document) {
  if(!object(document)||document.errors!==undefined&&(!Array.isArray(document.errors)||document.errors.length))fail();
  const schema=document.data?.__schema??document.__schema;
  if(!object(schema))fail();
  const all=list(schema.types),types=new Map(),warnings=new Set();
  for(const type of all) {
    if(!object(type)||typeof type.name!=='string'||!kinds.has(type.kind))fail();
    if(type.name.startsWith('__'))continue;
    name(type.name);if(types.has(type.name)||builtinScalars.has(type.name)&&type.kind!=='SCALAR')fail();types.set(type.name,type);
  }
  let fieldsSeen=0;
  const members=(items)=>{const values=unique(list(items));fieldsSeen+=values.length;if(fieldsSeen>20000)fail();return values;};
  function reference(ref,input=false,depth=0) {
    if(!object(ref)||depth>32)fail();
    if(ref.kind==='NON_NULL'||ref.kind==='LIST') {
      if(ref.name!=null||!object(ref.ofType)||ref.kind==='NON_NULL'&&ref.ofType.kind==='NON_NULL')fail();
      const child=reference(ref.ofType,input,depth+1);return ref.kind==='LIST'?'['+child+']':child+'!';
    }
    const n=name(ref.name),type=types.get(n);
    if(!type||ref.kind!==type.kind||ref.ofType!=null||input&&!['SCALAR','ENUM','INPUT_OBJECT'].includes(type.kind)||!input&&type.kind==='INPUT_OBJECT')fail();
    return n;
  }
  function deprecated(item) {
    if(item.isDeprecated===undefined)return '';
    if(typeof item.isDeprecated!=='boolean')fail();
    if(!item.isDeprecated)return '';
    if(typeof item.deprecationReason!=='string')fail();
    return ' @deprecated(reason: '+JSON.stringify(item.deprecationReason)+')';
  }
  function inputValue(item,indent='') {
    const type=reference(item.type,true),defaultValue=item.defaultValue;
    // A missing property means the introspection query omitted default-value evidence.
    if(defaultValue===undefined)fail();
    const literal=defaultValue===null?'':' = '+constantLiteral(defaultValue);
    if(item.isDeprecated&&item.type.kind==='NON_NULL'&&defaultValue===null)fail();
    return description(item.description,indent)+indent+name(item.name)+': '+type+literal+deprecated(item);
  }
  function args(items) {
    const values=members(items);return values.length?'(\n'+values.map(item=>inputValue(item,'    ')).join('\n')+'\n  )':'';
  }
  function interfaces(type) {
    const items=unique(list(type.interfaces));
    for(const ref of items)if(ref.kind!=='INTERFACE'||types.get(ref.name)?.kind!=='INTERFACE')fail();
    return items.length?' implements '+items.map(ref=>name(ref.name)).join(' & '):'';
  }
  const roots=[],rootNames=new Set();
  for(const [operation,key] of [['query','queryType'],['mutation','mutationType'],['subscription','subscriptionType']]) {
    const root=schema[key];if(root==null){if(operation==='query')fail();continue;}
    const n=name(root.name);if(types.get(n)?.kind!=='OBJECT'||rootNames.has(n))fail();rootNames.add(n);roots.push('  '+operation+': '+n);
  }
  const out=[description(schema.description)+'schema {\n'+roots.join('\n')+'\n}'];
  for(const type of types.values()) {
    const n=name(type.name),desc=description(type.description);
    switch(type.kind) {
      case 'SCALAR': {
        if(builtinScalars.has(n))break;
        if(type.specifiedByURL===undefined)warnings.add('Scalar specifiedByURL was not provided; omitted annotations may be unknown.');
        if(type.specifiedByURL!=null&&typeof type.specifiedByURL!=='string')fail();
        out.push(desc+'scalar '+n+(type.specifiedByURL?' @specifiedBy(url: '+JSON.stringify(type.specifiedByURL)+')':''));break;
      }
      case 'OBJECT':case 'INTERFACE': {
        const fields=members(type.fields);if(!fields.length)fail();
        out.push(desc+(type.kind==='OBJECT'?'type ':'interface ')+n+interfaces(type)+' {\n'+fields.map(field=>
          description(field.description,'  ')+'  '+name(field.name)+args(field.args)+': '+reference(field.type)+deprecated(field)).join('\n')+'\n}');break;
      }
      case 'INPUT_OBJECT': {
        if(type.isOneOf===undefined)warnings.add('Input isOneOf was not provided; omitted OneOf constraints may be unknown.');
        const fields=members(type.inputFields);if(!fields.length||type.isOneOf!==undefined&&type.isOneOf!==null&&typeof type.isOneOf!=='boolean')fail();
        if(type.isOneOf&&fields.some(field=>field.type.kind==='NON_NULL'||field.defaultValue!==null))fail();
        out.push(desc+'input '+n+(type.isOneOf?' @oneOf':'')+' {\n'+fields.map(field=>inputValue(field,'  ')).join('\n')+'\n}');break;
      }
      case 'ENUM': {
        const values=members(type.enumValues);if(!values.length)fail();
        out.push(desc+'enum '+n+' {\n'+values.map(value=>{if(['true','false','null'].includes(value.name))fail();return description(value.description,'  ')+'  '+name(value.name)+deprecated(value);}).join('\n')+'\n}');break;
      }
      case 'UNION': {
        const possible=unique(list(type.possibleTypes));if(!possible.length)fail();
        for(const item of possible)if(item.kind!=='OBJECT'||types.get(item.name)?.kind!=='OBJECT')fail();
        out.push(desc+'union '+n+' = '+possible.map(item=>name(item.name)).join(' | '));break;
      }
      default:fail();
    }
  }
  const directives=unique(list(schema.directives,256));
  for(const directive of directives) {
    const n=name(directive.name),where=list(directive.locations,32);
    if(!where.length||new Set(where).size!==where.length||where.some(item=>!locations.has(item))||directive.isRepeatable!==undefined&&typeof directive.isRepeatable!=='boolean')fail();
    if(directive.isRepeatable===undefined&&!builtinDirectives.has(n))warnings.add('Directive isRepeatable was not provided; repeatability may be unknown.');
    const parameters=args(directive.args);
    if(!builtinDirectives.has(n))out.push(description(directive.description)+'directive @'+n+parameters+(directive.isRepeatable?' repeatable':'')+' on '+where.join(' | '));
  }
  const text='# Reconstructed from saved introspection; no query was sent.\n# Applied custom directives, resolvers and authorization are not recoverable from introspection.\n# Structural conversion does not replace full GraphQL schema validation.\n\n'+[...warnings].map(warning=>'# Limitation: '+warning+'\n').join('')+out.join('\n\n')+'\n';
  if(byteLength(text)>1048576)fail();
  return {text,type_count:types.size,directive_count:directives.length,warnings:[...warnings]};
}

return {introspectionSDL,constantLiteral};
})();
function capturedSDL(source) {
  const record = source.evidence.record, body = record.response.body;
  if (record.state !== 'complete' || record.status !== 200 || body.state !== 'available' || body.truncated || body.text && body.base64)
    throw new TypeError('Select a complete retained HTTP 200 introspection JSON response body.');
  const text = body.base64 ? new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(decodeBase64(body.base64)) : body.text;
  const result = graphql.introspectionSDL(client.capturedClientJSON(text,new Map()));
  return {...result,text:'# Saved REB identity: '+JSON.stringify(source.identity)+'\n'+result.text};
}
return {pythonProject,...har,...graphql,capturedSDL,validateTimingEvidence};
})();
if (typeof module === 'object' && module?.exports && typeof require === 'function') module.exports = capturedExportFormats;
