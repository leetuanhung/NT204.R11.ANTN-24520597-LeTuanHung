"""Unit test cho ids/output.py (ghi JSON Lines).

Chạy:  python -m unittest -v tests.test_output
"""

import json
import os
import tempfile
import unittest

from ids.output import JsonlWriter, read_jsonl


class JsonlWriterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "events.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def read_lines(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read().splitlines()

    def test_one_json_object_per_line(self):
        events = [{"packet_id": 1, "src_ip": "10.0.0.1"}, {"packet_id": 2, "src_ip": "10.0.0.2"}]
        with JsonlWriter(self.path) as w:
            for e in events:
                w.write(e)
        lines = self.read_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual([json.loads(line) for line in lines], events)
        self.assertEqual(lines[0], '{"packet_id":1,"src_ip":"10.0.0.1"}')   # Gọn, giống ví dụ của đề
        self.assertEqual(w.count, 2)

    def test_nested_values_and_newlines_stay_on_one_line(self):
        event = {"http": {"file_data": "line1\nline2\r\n"}, "list": [1, None, True]}
        with JsonlWriter(self.path) as w:
            w.write(event)
        lines = self.read_lines()
        self.assertEqual(len(lines), 1)               # Ký tự xuống dòng được escape thành \n
        self.assertEqual(json.loads(lines[0]), event)

    def test_unicode_kept(self):
        with JsonlWriter(self.path) as w:
            w.write({"subject": "Hóa đơn tháng 9", "bad": "�"})
        self.assertIn("Hóa đơn tháng 9", self.read_lines()[0])

    def test_flushed_before_close(self):
        # Live capture: file phải đọc được ngay trong lúc còn đang ghi
        w = JsonlWriter(self.path)
        w.write({"packet_id": 1})
        self.assertEqual(self.read_lines(), ['{"packet_id":1}'])
        w.close()

    def test_creates_folder(self):
        path = os.path.join(self.tmp.name, "a", "b", "events.jsonl")
        with JsonlWriter(path) as w:
            w.write({"x": 1})
        self.assertTrue(os.path.exists(path))

    def test_overwrite_and_append(self):
        with JsonlWriter(self.path) as w:
            w.write({"run": 1})
        with JsonlWriter(self.path) as w:
            w.write({"run": 2})
        self.assertEqual(len(self.read_lines()), 1)   # Mặc định ghi đè
        with JsonlWriter(self.path, append=True) as w:
            w.write({"run": 3})
        self.assertEqual([e["run"] for e in read_jsonl(self.path)], [2, 3])

    def test_closed_even_on_error(self):
        with self.assertRaises(RuntimeError):
            with JsonlWriter(self.path) as w:
                w.write({"x": 1})
                raise RuntimeError("dừng giữa chừng")
        self.assertTrue(w._file.closed)
        self.assertEqual(len(self.read_lines()), 1)

    def test_read_jsonl_skips_blank_lines(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('{"a":1}\n\n{"a":2}\n')
        self.assertEqual([e["a"] for e in read_jsonl(self.path)], [1, 2])


if __name__ == "__main__":
    unittest.main()
