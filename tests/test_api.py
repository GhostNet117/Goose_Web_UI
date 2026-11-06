"""API helpers that need no running gateway."""
import base64

from goose_web.api import _resource_html


def test_resource_html_prefers_html_text():
    contents = [{"uri": "ui://x", "mimeType": "text/plain", "text": "plain"},
                {"uri": "ui://x", "mimeType": "text/html;profile=mcp-app", "text": "<b>app</b>"}]
    assert _resource_html(contents) == "<b>app</b>"


def test_resource_html_decodes_blob_and_falls_back():
    blob = base64.b64encode("<i>blob</i>".encode()).decode()
    assert _resource_html([{"uri": "ui://x", "mimeType": "text/html", "blob": blob}]) == "<i>blob</i>"
    assert _resource_html([{"uri": "ui://x", "text": "untyped"}]) == "untyped"
    assert _resource_html([{"uri": "ui://x", "blob": "!!not base64!!"}, "junk"]) is None
    assert _resource_html([]) is None
