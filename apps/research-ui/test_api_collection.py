import json
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from api_collection import (
    ApiCollectionConflict,
    ApiCollectionError,
    ApiCollectionStore,
    empty_api_collection,
    normalize_api_collection,
)
from server import ResearchHandler


def request_record(
    request_id: int = 10, folder_id: int = 2, name: str = "Create order"
) -> dict:
    return {
        "id": request_id,
        "folder_id": folder_id,
        "name": name,
        "url": "https://{{host}}/orders/{{order}}",
        "method": "POST",
        "headers": [
            {"name": "content-type", "value": "application/json"},
            {"name": "x-run", "value": "{{run}}"},
        ],
        "body": '{"order":"{{order}}"}',
        "timeout_ms": 15_000,
        "variables": [{"name": "order", "value": "42"}],
    }


def replacement(
    generation: int = 0,
    *,
    folders: Optional[list] = None,
    requests: Optional[list] = None,
) -> dict:
    return {
        "action": "replace_api_collection",
        "expected_generation": generation,
        "folders": folders
        if folders is not None
        else [
            {
                "id": 1,
                "name": "API Collection",
                "parent_id": None,
                "variables": [{"name": "host", "value": "api.test"}],
            },
            {
                "id": 2,
                "name": "Orders",
                "parent_id": 1,
                "variables": [{"name": "run", "value": "one"}],
            },
        ],
        "requests": requests if requests is not None else [request_record()],
    }


class ApiCollectionStoreTests(unittest.TestCase):
    def test_store_atomically_persists_bounded_collection_and_detects_conflicts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "collection.json"
            store = ApiCollectionStore(path)
            self.assertEqual(store.load(), empty_api_collection())

            saved = store.replace(replacement())
            self.assertEqual(saved["generation"], 1)
            self.assertEqual(saved["folders"][0]["variables"][0]["name"], "host")
            self.assertEqual(saved["requests"][0]["name"], "Create order")
            self.assertGreater(saved["requests"][0]["created_at_ms"], 0)
            self.assertEqual(
                saved["requests"][0]["created_at_ms"],
                saved["requests"][0]["updated_at_ms"],
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(ApiCollectionStore(path).load(), saved)

            unchanged = store.replace(replacement(generation=1))
            self.assertEqual(unchanged, saved)
            with self.assertRaises(ApiCollectionConflict):
                store.replace(replacement(generation=0))

            changed_request = request_record()
            changed_request["body"] = '{"order":"{{order}}","retry":true}'
            changed = store.replace(
                replacement(generation=1, requests=[changed_request])
            )
            self.assertEqual(changed["generation"], 2)
            self.assertEqual(
                changed["requests"][0]["created_at_ms"],
                saved["requests"][0]["created_at_ms"],
            )
            self.assertGreaterEqual(
                changed["requests"][0]["updated_at_ms"],
                saved["requests"][0]["updated_at_ms"],
            )

    def test_store_rejects_sensitive_cycles_duplicates_and_malformed_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ApiCollectionStore(Path(directory) / "collection.json")

            sensitive = request_record()
            sensitive["headers"] = [{"name": "Authorization", "value": "secret"}]
            with self.assertRaisesRegex(ApiCollectionError, "forbidden"):
                store.replace(replacement(requests=[sensitive]))

            duplicate = replacement()["folders"] + [
                {"id": 3, "name": "orders", "parent_id": 1, "variables": []}
            ]
            with self.assertRaisesRegex(ApiCollectionError, "duplicated"):
                store.replace(replacement(folders=duplicate))

            cycle = [
                {
                    "id": 1,
                    "name": "API Collection",
                    "parent_id": None,
                    "variables": [],
                },
                {"id": 2, "name": "A", "parent_id": 3, "variables": []},
                {"id": 3, "name": "B", "parent_id": 2, "variables": []},
            ]
            with self.assertRaisesRegex(ApiCollectionError, "hierarchy"):
                store.replace(replacement(folders=cycle, requests=[]))

            oversized_variables = replacement()["folders"]
            oversized_variables[0]["variables"] = [
                {"name": f"v{index}", "value": "x" * 4096}
                for index in range(9)
            ]
            with self.assertRaisesRegex(ApiCollectionError, "32 KiB"):
                store.replace(replacement(folders=oversized_variables, requests=[]))

            store.path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ApiCollectionError, "shape"):
                store.load()
            store.path.unlink()
            target = Path(directory) / "target.json"
            target.write_text(json.dumps(empty_api_collection()), encoding="utf-8")
            store.path.symlink_to(target)
            with self.assertRaisesRegex(ApiCollectionError, "regular file"):
                store.load()

    def test_document_rejects_generation_zero_with_saved_content(self) -> None:
        invalid = empty_api_collection()
        invalid["folders"][0]["variables"] = [{"name": "host", "value": "api.test"}]
        with self.assertRaisesRegex(ApiCollectionError, "generation zero"):
            normalize_api_collection(invalid)


class ApiCollectionHttpTests(unittest.TestCase):
    def test_http_get_replace_etag_conflict_and_origin_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous_store = ResearchHandler.api_collection_store
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.event_store = root / "events.jsonl"
            ResearchHandler.trace_store = root / "origin-trace.jsonl"
            ResearchHandler.signal_store = root / "request-signals.jsonl"
            ResearchHandler.artifact_store = root / "artifacts"
            ResearchHandler.api_collection_store = ApiCollectionStore(
                root / "collection.json"
            )
            ResearchHandler.broker_socket = None
            ResearchHandler.debugger = None
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(
                    f"{base_url}/api/api-collection"
                ) as response:
                    self.assertEqual(json.load(response)["generation"], 0)
                    self.assertEqual(
                        response.headers["ETag"], '"api-collection-0"'
                    )

                encoded = json.dumps(replacement()).encode("utf-8")
                save_request = urllib.request.Request(
                    f"{base_url}/api/api-collection/actions",
                    data=encoded,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(save_request) as response:
                    saved = json.load(response)
                    self.assertEqual(saved["generation"], 1)
                    self.assertEqual(
                        response.headers["ETag"], '"api-collection-1"'
                    )

                conditional = urllib.request.Request(
                    f"{base_url}/api/api-collection",
                    headers={"If-None-Match": '"api-collection-1"'},
                )
                with self.assertRaises(urllib.error.HTTPError) as not_modified:
                    urllib.request.urlopen(conditional)
                self.assertEqual(not_modified.exception.code, 304)

                with self.assertRaises(urllib.error.HTTPError) as conflict:
                    urllib.request.urlopen(save_request)
                self.assertEqual(conflict.exception.code, 409)

                rejected = urllib.request.Request(
                    f"{base_url}/api/api-collection",
                    headers={"Origin": "https://attacker.test"},
                )
                with self.assertRaises(urllib.error.HTTPError) as forbidden:
                    urllib.request.urlopen(rejected)
                self.assertEqual(forbidden.exception.code, 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2.0)
                ResearchHandler.api_collection_store = previous_store


if __name__ == "__main__":
    unittest.main()
