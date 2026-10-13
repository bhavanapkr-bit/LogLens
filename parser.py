import re
from typing import Iterator, TextIO, BinaryIO


LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+(.+?)\s+HTTP/[\d.]+"\s+'
    r'(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?\s*$'
)
    

def parse_log_line(line: str):
    """Parse one Apache/Nginx access-log line."""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    ip, timestamp, method, path, status, size, referer, user_agent = (
        match.groups()
    )

    return {
        "IP Address": ip,
        "Timestamp": timestamp,
        "Method": method,
        "Path": path,
        "Status Code": int(status),
        "Size": size,
        "Referer": referer or "",
        "User-Agent": user_agent or "",
        "Raw Log": line.rstrip("\r\n")
    }


def iter_log_records(file_obj: TextIO | BinaryIO) -> Iterator[dict]:
    """
    Read and parse one line at a time.
    Invalid lines are skipped without stopping the parser.
    """
    for raw_line in file_obj:
        if isinstance(raw_line, bytes):
            line = raw_line.decode("utf-8", errors="replace")
        else:
            line = raw_line

        record = parse_log_line(line)

        if record is not None:
            yield record
