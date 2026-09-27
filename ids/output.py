"""Ghi sự kiện ra file JSON Lines (mục 8 của đề): mỗi dòng là một JSON của một gói.

JSON Lines dễ dùng lại ở các bài IDS sau: đọc từng dòng bằng json.loads(), không cần nạp cả file,
và file đang ghi dở (live capture) vẫn đọc được các dòng đã xong.
"""

import json
import os


class JsonlWriter:
    """Dùng với "with": file luôn được đóng kể cả khi chương trình dừng giữa chừng."""

    def __init__(self, path: str, append: bool = False) -> None:
        self.path = path
        self.count = 0
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        # utf-8 để giữ nguyên tiếng Việt và ký tự lạ; "w" ghi đè, "a" ghi tiếp
        self._file = open(path, "a" if append else "w", encoding="utf-8")

    def write(self, event: dict) -> None:
        # separators gọn để file nhỏ hơn; ensure_ascii=False để không đổi chữ có dấu thành \\uXXXX
        self._file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        # Ghi xuống đĩa ngay: live capture có thể bị dừng bằng Ctrl+C bất cứ lúc nào,
        # và module khác có thể đang đọc file theo thời gian thực
        self._file.flush()
        self.count += 1

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_jsonl(path: str):
    """Đọc lại file JSON Lines, trả về từng event. Dùng cho test và cho các bài IDS sau."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)
