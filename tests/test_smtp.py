"""Unit test cho ids/parsers/smtp.py.

Chạy:  python -m unittest -v tests.test_smtp
"""

import base64
import json
import unittest

from ids.parsers.errors import ParseError
from ids.parsers.smtp import parse_smtp


class RequiredCasesTest(unittest.TestCase):
    """Hai test case bắt buộc của đề liên quan đến SMTP."""

    def test_smtp_commands_helo_mail_rcpt(self):
        cases = [
            (b"HELO client.example.com\r\n", "HELO", "client.example.com"),
            (b"EHLO client.example.com\r\n", "EHLO", "client.example.com"),
            (b"MAIL FROM:<alice@example.com>\r\n", "MAIL", "FROM:<alice@example.com>"),
            (b"RCPT TO:<bob@example.org>\r\n", "RCPT", "TO:<bob@example.org>"),
        ]
        for payload, command, parameter in cases:
            with self.subTest(command):
                s = parse_smtp(payload)
                self.assertEqual(s["type"], "request")
                self.assertEqual(s["req"], {"command": command, "parameter": parameter})
                self.assertEqual(s["command_line"], payload.decode().strip())
        self.assertEqual(parse_smtp(cases[1][0])["helo"], "client.example.com")
        self.assertEqual(parse_smtp(cases[2][0])["mail_from"], "alice@example.com")
        self.assertEqual(parse_smtp(cases[3][0])["rcpt_to"], ["bob@example.org"])

    def test_smtp_response_status_code(self):
        cases = [
            (b"220 mx.example.com ESMTP Postfix\r\n", 220, "mx.example.com ESMTP Postfix"),
            (b"250 OK\r\n", 250, "OK"),
            (b"354 End data with <CR><LF>.<CR><LF>\r\n", 354, "End data with <CR><LF>.<CR><LF>"),
            (b"550 5.1.1 User unknown\r\n", 550, "5.1.1 User unknown"),
            (b"221 Bye\r\n", 221, "Bye"),
        ]
        for payload, code, parameter in cases:
            with self.subTest(code):
                s = parse_smtp(payload)
                self.assertEqual(s["type"], "response")
                self.assertEqual(s["response"]["code"], code)
                self.assertEqual(s["response"]["parameter"], parameter)
                self.assertFalse(s["response"]["multiline"])
                self.assertTrue(s["response"]["complete"])


class CommandTest(unittest.TestCase):
    def test_lowercase_command_normalized(self):
        s = parse_smtp(b"ehlo Client.Local\r\n")
        self.assertEqual(s["req"]["command"], "EHLO")
        self.assertEqual(s["helo"], "Client.Local")

    def test_simple_commands(self):
        for command in ["DATA", "QUIT", "RSET", "NOOP", "STARTTLS", "HELP"]:
            with self.subTest(command):
                s = parse_smtp(f"{command}\r\n".encode())
                self.assertEqual(s["req"], {"command": command, "parameter": ""})

    def test_mail_from_with_parameters(self):
        s = parse_smtp(b"MAIL FROM:<alice@example.com> SIZE=1234 BODY=8BITMIME\r\n")
        self.assertEqual(s["mail_from"], "alice@example.com")

    def test_null_sender(self):
        # MAIL FROM:<> dùng cho thư báo lỗi (bounce)
        self.assertEqual(parse_smtp(b"MAIL FROM:<>\r\n")["mail_from"], "")

    def test_address_without_brackets(self):
        s = parse_smtp(b"MAIL FROM: alice@example.com\r\n")
        self.assertEqual(s["mail_from"], "alice@example.com")

    def test_pipelining_multiple_commands(self):
        s = parse_smtp(b"MAIL FROM:<a@x.com>\r\nRCPT TO:<b@y.com>\r\nRCPT TO:<c@y.com>\r\nDATA\r\n")
        self.assertEqual([c["command"] for c in s["commands"]], ["MAIL", "RCPT", "RCPT", "DATA"])
        self.assertEqual(s["mail_from"], "a@x.com")
        self.assertEqual(s["rcpt_to"], ["b@y.com", "c@y.com"])
        self.assertEqual(s["req"]["command"], "MAIL")        # Lệnh đầu tiên
        self.assertEqual(s["line_count"], 4)

    def test_data_content_in_same_packet(self):
        s = parse_smtp(b"DATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\n")
        self.assertEqual(s["req"]["command"], "DATA")
        self.assertEqual(s["data"]["headers"], {"subject": "hi"})
        self.assertTrue(s["data"]["end_of_data"])

    def test_bad_mail_syntax_counted(self):
        s = parse_smtp(b"MAIL alice@example.com\r\n")
        self.assertNotIn("mail_from", s)
        self.assertEqual(s["unknown_lines"], 1)

    def test_unknown_lines_after_command(self):
        s = parse_smtp(b"NOOP\r\nFOOBAR something\r\n")
        self.assertEqual(len(s["commands"]), 1)
        self.assertEqual(s["unknown_lines"], 1)

    def test_command_split_across_packets(self):
        s = parse_smtp(b"MAIL FROM:<alice@exa")
        self.assertTrue(s["incomplete_line"])
        self.assertEqual(s["req"]["command"], "MAIL")

    def test_many_commands_capped(self):
        s = parse_smtp(b"NOOP\r\n" * 500)
        self.assertEqual(len(s["commands"]), 100)
        self.assertEqual(s["line_count"], 500)


class AuthTest(unittest.TestCase):
    PASSWORD = "S3cret!pass"

    def assert_no_password(self, result: dict, secret: str) -> None:
        text = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(secret, text)

    def test_auth_plain(self):
        blob = base64.b64encode(f"\0alice\0{self.PASSWORD}".encode()).decode()
        s = parse_smtp(f"AUTH PLAIN {blob}\r\n".encode())
        self.assertEqual(s["auth"], {"mechanism": "PLAIN", "username": "alice", "password_present": True})
        self.assertEqual(s["command_line"], "AUTH PLAIN ***")
        self.assert_no_password(s, self.PASSWORD)
        self.assert_no_password(s, blob)                  # Cả dạng base64 cũng không được lộ

    def test_auth_login_with_initial_username(self):
        s = parse_smtp(b"AUTH LOGIN " + base64.b64encode(b"alice") + b"\r\n")
        self.assertEqual(s["auth"]["mechanism"], "LOGIN")
        self.assertEqual(s["auth"]["username"], "alice")

    def test_auth_login_without_data(self):
        s = parse_smtp(b"AUTH LOGIN\r\n")
        self.assertEqual(s["auth"], {"mechanism": "LOGIN"})
        self.assertEqual(s["command_line"], "AUTH LOGIN")

    def test_auth_login_password_line_is_masked(self):
        # Mật khẩu của AUTH LOGIN được gửi thành một dòng base64 riêng
        blob = base64.b64encode(self.PASSWORD.encode())
        s = parse_smtp(blob + b"\r\n")
        self.assertEqual(s["type"], "auth_data")
        self.assertEqual(s["auth_data"], {"len": len(blob)})
        self.assert_no_password(s, blob.decode())

    def test_auth_bad_base64(self):
        s = parse_smtp(b"AUTH PLAIN !!notbase64!!\r\n")
        self.assertTrue(s["auth"]["decode_error"])
        self.assertEqual(s["command_line"], "AUTH PLAIN ***")

    def test_auth_plain_wrong_structure(self):
        s = parse_smtp(b"AUTH PLAIN " + base64.b64encode(b"no-null-bytes") + b"\r\n")
        self.assertTrue(s["auth"]["decode_error"])


class ResponseTest(unittest.TestCase):
    def test_multiline_ehlo_response(self):
        s = parse_smtp(b"250-mx.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
                       b"250-starttls\r\n250 8BITMIME\r\n")
        r = s["response"]
        self.assertEqual(r["code"], 250)
        self.assertEqual(r["parameter"], "mx.example.com")
        self.assertTrue(r["multiline"])
        self.assertTrue(r["complete"])
        self.assertEqual(r["extensions"], ["PIPELINING", "SIZE 10240000", "STARTTLS", "8BITMIME"])

    def test_multiline_split_across_packets(self):
        r = parse_smtp(b"250-mx.example.com\r\n250-PIPELINING\r\n")["response"]
        self.assertFalse(r["complete"])

    def test_enhanced_status_code(self):
        r = parse_smtp(b"250 2.1.0 Ok\r\n")["response"]
        self.assertEqual(r["enhanced_status"], "2.1.0")
        self.assertNotIn("enhanced_status", parse_smtp(b"250 OK\r\n")["response"])

    def test_code_without_text(self):
        r = parse_smtp(b"250\r\n")["response"]
        self.assertEqual((r["code"], r["parameter"]), (250, ""))

    def test_inconsistent_codes_counted(self):
        s = parse_smtp(b"250-first\r\n550 second\r\nnot a response\r\n")
        self.assertEqual(s["response"]["code"], 250)
        self.assertEqual(s["malformed_lines"], 2)

    def test_auth_challenge(self):
        r = parse_smtp(b"334 VXNlcm5hbWU6\r\n")["response"]   # base64 của "Username:"
        self.assertEqual((r["code"], r["parameter"]), (334, "VXNlcm5hbWU6"))


class DataTest(unittest.TestCase):
    def test_message_content(self):
        s = parse_smtp(b"From: Alice <alice@example.com>\r\nTo: bob@example.org\r\n"
                       b"Subject: Invoice\r\nDate: Fri, 25 Sep 2026 10:00:00 +0700\r\n"
                       b"X-Mailer: test\r\n\r\nPlease see attached.\r\n.\r\n")
        self.assertEqual(s["type"], "data")
        d = s["data"]
        self.assertEqual(d["headers"], {"from": "Alice <alice@example.com>", "to": "bob@example.org",
                                        "subject": "Invoice", "date": "Fri, 25 Sep 2026 10:00:00 +0700"})
        self.assertTrue(d["end_of_data"])
        self.assertIn("Please see attached.", d["message"])
        self.assertNotIn("\n.", d["message"])               # Dòng "." kết thúc không nằm trong thư

    def test_body_only_packet(self):
        d = parse_smtp(b"...middle of a long email body...\r\nmore text\r\n")["data"]
        self.assertNotIn("headers", d)
        self.assertFalse(d["end_of_data"])

    def test_long_message_capped(self):
        d = parse_smtp(b"A" * 5000 + b"\r\n.\r\n")["data"]
        self.assertEqual(len(d["message"]), 1024)
        self.assertTrue(d["message_truncated"])

    def test_non_utf8_bytes(self):
        s = parse_smtp(b"Subject: \xff\xfe\r\n\r\n\xc3\x28\r\n")
        self.assertIn("�", s["data"]["headers"]["subject"])

    def test_lf_only(self):
        s = parse_smtp(b"EHLO a\nMAIL FROM:<x@y>\n")
        self.assertEqual(s["mail_from"], "x@y")


class ErrorTest(unittest.TestCase):
    def test_empty_payload(self):
        with self.assertRaises(ParseError):
            parse_smtp(b"")


if __name__ == "__main__":
    unittest.main()
