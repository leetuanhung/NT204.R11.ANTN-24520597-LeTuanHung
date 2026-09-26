"""Unit test cho ids/parsers/http.py.

Chạy:  python -m unittest -v tests.test_http
"""

import unittest

from ids.parsers.errors import ParseError
from ids.parsers.http import parse_http

GET = (b"GET /search?q=ids HTTP/1.1\r\n"
       b"Host: example.com\r\n"
       b"User-Agent: Mozilla/5.0\r\n"
       b"Accept: text/html\r\n"
       b"Cookie: session=abc123\r\n"
       b"Referer: http://example.com/\r\n"
       b"Connection: keep-alive\r\n"
       b"\r\n")

POST_BODY = b"username=admin&password=secret"
POST = (b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(POST_BODY)).encode() + b"\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0\r\n"
        b"X-Forwarded-For: 203.0.113.9\r\n"
        b"\r\n" + POST_BODY)

RESPONSE = (b"HTTP/1.1 302 Found\r\n"
            b"Server: nginx/1.24\r\n"
            b"Location: /home\r\n"
            b"Set-Cookie: sid=1; Path=/\r\n"
            b"Set-Cookie: theme=dark, light\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: 11\r\n"
            b"\r\n"
            b"redirecting")


class RequiredCasesTest(unittest.TestCase):
    """Ba test case bắt buộc của đề liên quan đến HTTP."""

    def test_http_get(self):
        h = parse_http(GET)
        self.assertEqual(h["type"], "request")
        self.assertEqual(h["request"]["method"], "GET")
        self.assertEqual(h["request"]["uri"], "/search?q=ids")
        self.assertEqual(h["request"]["version"], "HTTP/1.1")
        self.assertEqual(h["request"]["full_uri"], "http://example.com/search?q=ids")
        self.assertEqual(h["line"], "GET /search?q=ids HTTP/1.1")
        self.assertEqual(h["host"], "example.com")
        self.assertEqual(h["user_agent"], "Mozilla/5.0")
        self.assertEqual(h["accept"], "text/html")
        self.assertEqual(h["cookie"], "session=abc123")
        self.assertEqual(h["referer"], "http://example.com/")
        self.assertEqual(h["connection"], "keep-alive")
        self.assertTrue(h["header_complete"])
        self.assertEqual(h["body_len"], 0)
        self.assertTrue(h["body_complete"])      # GET không khai báo độ dài thì không có body
        self.assertNotIn("file_data", h)

    def test_http_post_with_body(self):
        h = parse_http(POST)
        self.assertEqual(h["request"]["method"], "POST")
        self.assertEqual(h["content_type"], "application/x-www-form-urlencoded")
        self.assertEqual(h["content_length"], len(POST_BODY))
        self.assertFalse(h["content_length_invalid"])
        self.assertEqual(h["authorization"], "Basic YWRtaW46c2VjcmV0")
        self.assertEqual(h["x_forwarded_for"], "203.0.113.9")
        self.assertEqual(h["file_data"], "username=admin&password=secret")
        self.assertEqual(h["body_len"], len(POST_BODY))
        self.assertTrue(h["body_complete"])

    def test_http_response_status_and_headers(self):
        h = parse_http(RESPONSE)
        self.assertEqual(h["type"], "response")
        self.assertEqual(h["response"], {"version": "HTTP/1.1", "code": 302, "phrase": "Found"})
        self.assertEqual(h["server"], "nginx/1.24")
        self.assertEqual(h["location"], "/home")
        self.assertEqual(h["content_type"], "text/html; charset=utf-8")
        self.assertEqual(h["set_cookie"], ["sid=1; Path=/", "theme=dark, light"])
        self.assertEqual(h["file_data"], "redirecting")
        self.assertNotIn("request", h)


class HeaderTest(unittest.TestCase):
    def test_header_names_case_insensitive(self):
        h = parse_http(b"GET / HTTP/1.1\r\nHOST: A.com\r\nuser-AGENT: x\r\n\r\n")
        self.assertEqual(h["host"], "A.com")
        self.assertEqual(h["user_agent"], "x")
        self.assertIn("host", h["headers"])

    def test_all_headers_kept(self):
        h = parse_http(b"GET / HTTP/1.1\r\nHost: a\r\nX-Custom: 1\r\nDNT: 1\r\n\r\n")
        self.assertEqual(h["headers"], {"host": "a", "x-custom": "1", "dnt": "1"})

    def test_duplicate_headers_joined(self):
        h = parse_http(b"GET / HTTP/1.1\r\nAccept: a\r\nAccept: b\r\n\r\n")
        self.assertEqual(h["accept"], "a, b")

    def test_value_whitespace_trimmed(self):
        h = parse_http(b"GET / HTTP/1.1\r\nHost:    spaced.com   \r\n\r\n")
        self.assertEqual(h["host"], "spaced.com")

    def test_obs_fold_continuation(self):
        h = parse_http(b"GET / HTTP/1.1\r\nUser-Agent: part1\r\n  part2\r\n\r\n")
        self.assertEqual(h["user_agent"], "part1 part2")
        self.assertEqual(h["malformed_lines"], 0)

    def test_malformed_header_lines_counted(self):
        h = parse_http(b"GET / HTTP/1.1\r\nno colon here\r\nBad Name: x\r\n : x\r\nHost: a\r\n\r\n")
        self.assertEqual(h["malformed_lines"], 3)
        self.assertEqual(h["host"], "a")           # Dòng hợp lệ vẫn đọc được

    def test_lf_only_line_endings(self):
        h = parse_http(b"GET /x HTTP/1.0\nHost: a\n\nbody-ignored")
        self.assertEqual(h["request"]["version"], "HTTP/1.0")
        self.assertEqual(h["host"], "a")
        self.assertTrue(h["header_complete"])

    def test_absolute_uri_via_proxy(self):
        h = parse_http(b"GET http://other.com/p HTTP/1.1\r\nHost: other.com\r\n\r\n")
        self.assertEqual(h["request"]["full_uri"], "http://other.com/p")

    def test_no_host_no_full_uri(self):
        h = parse_http(b"GET / HTTP/1.0\r\n\r\n")
        self.assertNotIn("full_uri", h["request"])

    def test_non_ascii_header_does_not_crash(self):
        h = parse_http(b"GET / HTTP/1.1\r\nUser-Agent: \xff\xfe\xc3\x28\r\n\r\n")
        self.assertEqual(len(h["user_agent"]), 4)   # latin-1: mỗi byte thành một ký tự


class StatusLineTest(unittest.TestCase):
    def test_phrase_with_spaces(self):
        h = parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n")
        self.assertEqual(h["response"]["phrase"], "Not Found")

    def test_empty_phrase_allowed(self):
        h = parse_http(b"HTTP/1.1 204\r\n\r\n")
        self.assertEqual(h["response"]["code"], 204)
        self.assertEqual(h["response"]["phrase"], "")

    def test_all_methods(self):
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"]:
            with self.subTest(method):
                self.assertEqual(parse_http(f"{method} / HTTP/1.1\r\n\r\n".encode())
                                 ["request"]["method"], method)


class BodyTest(unittest.TestCase):
    def test_partial_body(self):
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-part")
        self.assertEqual(h["content_length"], 100)
        self.assertEqual(h["body_len"], 9)
        self.assertFalse(h["body_complete"])

    def test_extra_bytes_after_body_ignored(self):
        # Hai request nối tiếp trong cùng một gói (pipelining): chỉ lấy body của request đầu
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET / HTTP/1.1\r\n\r\n")
        self.assertEqual(h["file_data"], "abc")
        self.assertEqual(h["body_len"], 3)
        self.assertTrue(h["body_complete"])

    def test_headers_cut_off(self):
        h = parse_http(b"GET / HTTP/1.1\r\nHost: a\r\nUser-Ag")
        self.assertFalse(h["header_complete"])
        self.assertFalse(h["body_complete"])
        self.assertEqual(h["host"], "a")
        self.assertEqual(h["malformed_lines"], 1)   # Dòng bị cắt dở không có ":"

    def test_invalid_content_length(self):
        for value in [b"abc", b"-5", b"1e3", b""]:
            with self.subTest(value=value):
                h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: " + value + b"\r\n\r\nxyz")
                self.assertIsNone(h["content_length"])
                self.assertTrue(h["content_length_invalid"])

    def test_non_ascii_digits_in_content_length(self):
        # Byte 0xB3 giải mã latin-1 thành "³": str.isdigit() coi là chữ số nhưng int() thì lỗi
        for value in [b"\xb3", b"1\xb9", b"\xb23"]:
            with self.subTest(value=value):
                h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: " + value + b"\r\n\r\nxyz")
                self.assertIsNone(h["content_length"])
                self.assertTrue(h["content_length_invalid"])

    def test_conflicting_content_length(self):
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 10\r\n\r\nabc")
        self.assertTrue(h["content_length_invalid"])

    def test_repeated_same_content_length_is_ok(self):
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc")
        self.assertFalse(h["content_length_invalid"])
        self.assertEqual(h["content_length"], 3)

    def test_chunked(self):
        body = b"5\r\nhello\r\n0\r\n\r\n"
        h = parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
        self.assertTrue(h["chunked"])
        self.assertEqual(h["transfer_encoding"], "chunked")
        self.assertTrue(h["body_complete"])
        self.assertEqual(h["body_len"], len(body))

    def test_chunked_incomplete(self):
        h = parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        self.assertFalse(h["body_complete"])

    def test_cl_te_conflict_flag(self):
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n"
                       b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.assertTrue(h["cl_te_conflict"])
        self.assertTrue(h["chunked"])

    def test_response_without_length_is_unknown(self):
        h = parse_http(b"HTTP/1.0 200 OK\r\n\r\nsome data until close")
        self.assertIsNone(h["body_complete"])

    def test_binary_body_does_not_crash(self):
        h = parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x89PNG")
        self.assertEqual(h["body_len"], 4)
        self.assertIn("�", h["file_data"])     # Byte 0x89 không phải UTF-8 được thay thế

    def test_long_body_text_capped(self):
        h = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 3000\r\n\r\n" + b"A" * 3000)
        self.assertEqual(len(h["file_data"]), 1024)
        self.assertTrue(h["file_data_truncated"])
        self.assertEqual(h["body_len"], 3000)


class NotHttpStartTest(unittest.TestCase):
    def test_continuation(self):
        for payload in [b"...rest of a body...", b"get / http/1.1\r\n\r\n", b"\x16\x03\x01\x00"]:
            with self.subTest(payload=payload):
                self.assertEqual(parse_http(payload), {"type": "continuation", "len": len(payload)})

    def test_empty_payload_is_error(self):
        with self.assertRaises(ParseError):
            parse_http(b"")


if __name__ == "__main__":
    unittest.main()
