"""
Parser for Zeek (formerly Bro) conn.log files.
Zeek is the industry-standard network monitoring tool.
"""

import re
import pandas as pd
from app.parsers.base import BaseParser


DEFAULT_CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes", "tunnel_parents",
]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_TS_RE = re.compile(r"^\d{9,10}(\.\d+)?$")


class ZeekParser(BaseParser):
    """
    Parses Zeek conn.log format.

    Handles two variants:
      1. Standard export with '#separator'/'#fields' header (tab-separated).
      2. Headerless raw conn.log (tab- or space-separated) - common when
         logs are dumped/converted without Zeek's metadata comment lines.
         Detected via column count + content heuristics instead of
         requiring the header.
    """

    @property
    def format_name(self) -> str:
        return "Zeek conn.log"

    def _get_lines(self, file_content: bytes):
        text = file_content.decode("utf-8", errors="ignore")
        return text.split("\n")

    def _has_fields_header(self, lines) -> bool:
        return any("#fields" in line for line in lines[:10])

    def _detect_headerless(self, lines):
        first = next((l for l in lines if l.strip() and not l.startswith("#")), None)
        if not first:
            return None

        tokens = first.split("\t") if "\t" in first else first.split()
        n = len(tokens)

        if not (18 <= n <= 24):
            return None
        if not _TS_RE.match(tokens[0]):
            return None
        if not (_IP_RE.match(tokens[2]) or (n > 4 and _IP_RE.match(tokens[4]))):
            return None

        return "\t" if "\t" in first else "whitespace"

    def can_parse(self, file_content: bytes, filename: str) -> bool:
        try:
            lines = self._get_lines(file_content)
            if self._has_fields_header(lines):
                return True
            return self._detect_headerless(lines) is not None
        except Exception:
            return False

    def parse(self, file_content: bytes) -> pd.DataFrame:
        lines = self._get_lines(file_content)
        if self._has_fields_header(lines):
            return self._parse_with_header(lines)
        return self._parse_headerless(lines)

    def _parse_with_header(self, lines) -> pd.DataFrame:
        field_line = next((l for l in lines if l.startswith("#fields")), None)
        if not field_line:
            raise ValueError("Could not find #fields header in Zeek log")
        columns = field_line.replace("#fields", "").strip().split("\t")
        data_lines = [l for l in lines if l and not l.startswith("#")]
        data = [line.split("\t") for line in data_lines]
        return pd.DataFrame(data, columns=columns)

    def _parse_headerless(self, lines) -> pd.DataFrame:
        delimiter = self._detect_headerless(lines)
        if delimiter is None:
            raise ValueError("Could not detect Zeek headerless log structure")

        data_lines = [l for l in lines if l.strip() and not l.startswith("#")]
        data = [line.split("\t") if delimiter == "\t" else line.split() for line in data_lines]

        n_cols = len(data[0])
        columns = list(DEFAULT_CONN_FIELDS[:n_cols])
        if n_cols > len(DEFAULT_CONN_FIELDS):
            extra = n_cols - len(DEFAULT_CONN_FIELDS)
            columns += ["label"] if extra == 1 else [f"extra_field_{i}" for i in range(extra)]

        return pd.DataFrame(data, columns=columns)
