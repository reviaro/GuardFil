"""Reject provider fetches hidden in otherwise client-side model requests.

Container network isolation does not constrain a provider fetching remote media.
Check before token counting too: counting may process the same media inputs.
URLs in ordinary text remain text; inline image data remains supported.
"""


REMOTE = "remote media URLs are forbidden in the executor"


def inline_image(url):
    """An image given inline, as a string (Responses API) or {"url": ...} (Chat Completions)."""
    if isinstance(url, dict) and set(url) <= {"url", "detail"}:
        url = url.get("url")
    return isinstance(url, str) and url.startswith("data:image/")


def remote_input_error(value):
    if isinstance(value, list):
        for item in value:
            error = remote_input_error(item)
            if error:
                return error
    elif isinstance(value, dict):
        url = value.get("image_url")
        if url is not None and not inline_image(url):
            return REMOTE
        # file_url (OpenAI) and Gemini's file_uri / fileUri name a file the provider fetches.
        for key in ("file_url", "file_uri", "fileUri"):
            if value.get(key) is not None:
                return REMOTE
        source = value.get("source")
        if isinstance(source, dict) and source.get("type") == "url":
            return REMOTE
        for item in value.values():
            error = remote_input_error(item)
            if error:
                return error
    return None
