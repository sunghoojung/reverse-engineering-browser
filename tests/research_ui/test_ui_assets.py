import threading
import unittest
from html.parser import HTMLParser
from urllib.request import urlopen

from server import LoopbackThreadingHTTPServer, ResearchHandler
from ui_test_support import UI_DIRECTORY


class AssetReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs) -> None:
        attributes = dict(attrs)
        if tag == "script":
            self.references.append((attributes.get("src"), "javascript"))
        elif tag == "link" and attributes.get("rel") == "stylesheet":
            self.references.append((attributes.get("href"), "text/css"))


class UiAssetsTest(unittest.TestCase):
    def test_page_assets_are_served_with_their_original_content_and_types(self) -> None:
        class Handler(ResearchHandler):
            ui_directory = UI_DIRECTORY

        server = LoopbackThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}/"
            with urlopen(base, timeout=2) as response:
                page = response.read().decode("utf-8")
            references = AssetReferences()
            references.feed(page)
            self.assertTrue(references.references)
            for path, content_type in references.references:
                with self.subTest(asset=path):
                    self.assertIsNotNone(path, "Application scripts must have an explicit source")
                    with urlopen(base + path, timeout=2) as response:
                        self.assertIn(content_type, response.headers["Content-Type"])
                        self.assertEqual(response.read(), (UI_DIRECTORY / path).read_bytes())
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
