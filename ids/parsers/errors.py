class ParseError(Exception):
    """Gói tin hỏng hoặc thiếu dữ liệu, parser không thể đọc tiếp.

    Parser ném lỗi này kèm thông điệp rõ ràng. Tầng gọi parser bắt lỗi
    để đánh dấu gói là malformed thay vì làm chương trình dừng.
    """
