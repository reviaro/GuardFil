import copy
import json
import unittest

from broker.messages_broker import Refused, check_request
from broker.test_messages_broker import CC_REQ
from research.t2a.openai_broker.live_broker import validate_and_prepare_request


class RemoteInputTest(unittest.TestCase):
    def test_openai_remote_media_and_hosted_shell_are_refused(self):
        base = {"model": "gpt-6-luna", "stream": True}
        for block in ({"type": "input_image", "image_url": "https://example.com/image.png"},
                      {"type": "input_file", "file_url": "https://example.com/file.pdf"},
                      {"type": "input_image", "image_url": "http://169.254.169.254/"}):
            req = dict(base, input=[{"role": "user", "content": [block]}])
            self.assertIn("remote media", validate_and_prepare_request(json.dumps(req).encode())[-1])
        for tool in ({"type": "shell", "environment": {"type": "container_auto"}},
                     {"type": "future_hosted_tool"}):
            req = dict(base, tools=[tool])
            self.assertIsNotNone(validate_and_prepare_request(json.dumps(req).encode())[-1])

    def test_anthropic_remote_media_nested_in_tool_results_is_refused(self):
        for typ in ("image", "document"):
            block = {"type": typ, "source": {"type": "url", "url": "https://example.com/a"}}
            for content in ([block], [{"type": "tool_result", "tool_use_id": "t", "content": [block]}]):
                req = copy.deepcopy(CC_REQ)
                req["messages"][0]["content"] = content
                with self.assertRaisesRegex(Refused, "remote media"):
                    check_request(req)

    def test_inline_images_and_text_urls_remain_available(self):
        req = {"model": "gpt-6-luna", "stream": True, "input": [{"role": "user", "content": [
            {"type": "input_image", "image_url": "data:image/png;base64,aGVsbG8="},
            {"type": "input_text", "text": "Explain https://example.com without fetching it"}]}]}
        self.assertIsNone(validate_and_prepare_request(json.dumps(req).encode())[-1])
        req = copy.deepcopy(CC_REQ)
        req["messages"][0]["content"] = [{"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": "aGVsbG8="}}]
        check_request(req)


class RemoteInputFormsTest(unittest.TestCase):
    def test_forms(self):
        from broker.input_boundary import remote_input_error as err
        self.assertIsNone(err({"type": "image_url", "image_url": {"url": "data:image/png;base64,aGk=", "detail": "low"}}))
        self.assertIsNotNone(err({"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}))
        self.assertIsNotNone(err({"type": "image_url", "image_url": {"url": "data:image/png;base64,aGk=",
                                                                     "file_url": "https://x"}}))
        self.assertIsNotNone(err([{"parts": [{"file_data": {"file_uri": "https://example.com/a", "mime_type": "x"}}]}]))
        self.assertIsNotNone(err({"fileData": {"fileUri": "gs://bucket/a"}}))
        self.assertIsNone(err({"text": "see https://example.com"}))



if __name__ == "__main__":
    unittest.main()
