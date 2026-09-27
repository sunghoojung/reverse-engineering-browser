#!/usr/bin/env python3
"""Call the existing local HTTP API by OpenAPI operation ID."""

import argparse
import json
import sys
from pathlib import Path

from api_client import ApiClient, ApiClientError, ApiContract, endpoint_file_url


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list documented HTTP operations")
    describe = commands.add_parser("describe", help="show an operation's contract")
    describe.add_argument("operation_id")

    call = commands.add_parser("call", help="send one documented HTTP operation")
    call.add_argument("operation_id")
    endpoint = call.add_mutually_exclusive_group(required=True)
    endpoint.add_argument("--base-url", help="explicit HTTP loopback server root")
    endpoint.add_argument("--endpoint-file", help="file written by server --endpoint-file")
    call.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                      help="path, query or header parameter; repeat as needed")
    call.add_argument("--body-file", metavar="PATH",
                      help="JSON request object; use - to read stdin")
    call.add_argument("--output", metavar="PATH",
                      help="required for binary content; use - for stdout")
    call.add_argument("--show-headers", action="store_true",
                      help="print response status and headers to stderr")
    call.add_argument("--timeout", type=float, default=30.0,
                      help="request timeout in seconds (default: 30)")
    return parser


def _parameters(items):
    result = {}
    for item in items:
        name, separator, value = item.partition("=")
        if not separator or not name:
            raise ApiClientError("--param must be NAME=VALUE")
        if name in result:
            raise ApiClientError(f"duplicate parameter: {name}")
        result[name] = value
    return result


def _body(path):
    if path is None:
        return None
    try:
        source = sys.stdin if path == "-" else Path(path).open(encoding="utf-8")
        if path == "-":
            raw = source.read()
        else:
            with source:
                raw = source.read()
        return json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ApiClientError(f"cannot read JSON body: {error}") from error


def _resolve_schema(document, schema):
    while "$ref" in schema:
        prefix = "#/components/schemas/"
        reference = schema["$ref"]
        if not reference.startswith(prefix):
            return schema
        schema = document["components"]["schemas"][reference[len(prefix):]]
    return schema


def _description(contract, operation):
    definition = operation.definition
    details = {
        "operationId": operation.operation_id,
        "method": operation.method,
        "path": operation.path,
        "summary": definition.get("summary", ""),
        "description": definition.get("description", ""),
        "parameters": operation.parameters,
        "requestBody": definition.get("requestBody"),
        "responses": definition["responses"],
    }
    body = definition.get("requestBody", {})
    schema = body.get("content", {}).get("application/json", {}).get("schema", {})
    schema = _resolve_schema(contract.document, schema)
    actions = []
    for variant in schema.get("oneOf", []):
        variant = _resolve_schema(contract.document, variant)
        action = variant.get("properties", {}).get("action", {}).get("const")
        if action:
            actions.append(action)
    if actions:
        details["actions"] = actions
    return details


def _http_error(response):
    try:
        result = response.json()
        if isinstance(result, dict) and isinstance(result.get("error"), str):
            detail = result["error"]
        else:
            detail = response.body.decode("utf-8", errors="replace")
    except ApiClientError:
        detail = response.body.decode("utf-8", errors="replace")
    return f"HTTP {response.status}: {detail.strip()[:500]}"


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        contract = ApiContract()
        if args.command == "list":
            for operation in sorted(contract.operations.values(), key=lambda item: item.operation_id):
                print(f"{operation.operation_id}\t{operation.method}\t{operation.path}")
            return 0
        operation = contract.operation(args.operation_id)
        if args.command == "describe":
            print(json.dumps(_description(contract, operation), indent=2, ensure_ascii=False))
            return 0

        if operation.returns_binary and args.output is None:
            raise ApiClientError("binary response requires --output PATH or --output -")
        if not operation.returns_binary and args.output is not None:
            raise ApiClientError("--output is only for binary responses")
        url = args.base_url or endpoint_file_url(args.endpoint_file)
        client = ApiClient(url, contract=contract, timeout=args.timeout)
        response = client.call(args.operation_id, _parameters(args.param), _body(args.body_file))
        if args.show_headers:
            print(json.dumps({"status": response.status, "headers": response.headers},
                             ensure_ascii=False), file=sys.stderr)
        if response.status == 304:
            return 0
        if response.status >= 400:
            print(_http_error(response), file=sys.stderr)
            return 1
        if operation.returns_binary:
            if args.output == "-":
                sys.stdout.buffer.write(response.body)
            else:
                with Path(args.output).open("xb") as output:
                    output.write(response.body)
        else:
            print(json.dumps(response.json(), indent=2, ensure_ascii=False))
        return 0
    except (ApiClientError, OSError) as error:
        print(f"reb-api: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
