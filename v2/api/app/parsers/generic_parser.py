"""
Fallback parser for arbitrary flow-record CSVs that don't match
CICFlowMeter or Zeek exactly (other NetFlow/IPFIX tools, Cisco flow
exports, custom loggers).

Maps common column-name variants onto the same canonical fields
ZeekParser already emits (ts, id.orig_h, id.orig_p, id.resp_h,
id.resp_p, proto, duration, orig_bytes, resp_bytes) rather than
inventing a new downstream schema.

NOTE: best-effort. Verify against the schema adapter before trusting
this beyond smoke-testing the pipeline.
"""

import pandas as pd
import io
from app.parsers.base import BaseParser


def _normalize(col: str) -> str:
    return col.strip().lower().replace("_", " ").replace("-", " ").replace(".", " ")


ALIAS_MAP = {
    "ts": ["ts", "timestamp", "time", "start time", "flow start"],
    "id.orig_h": ["id orig h", "src ip", "source ip", "srcaddr", "src addr", "ipv4 src addr"],
    "id.orig_p": ["id orig p", "src port", "source port", "srcport", "sport"],
    "id.resp_h": ["id resp h", "dst ip", "destination ip", "dstaddr", "dst addr", "ipv4 dst addr"],
    "id.resp_p": ["id resp p", "dst port", "destination port", "dstport", "dport"],
    "proto": ["proto", "protocol", "prot"],
    "duration": ["duration", "flow duration", "dur"],
    "orig_bytes": ["orig bytes", "src bytes", "fwd bytes", "total length of fwd packets", "in bytes"],
    "resp_bytes": ["resp bytes", "dst bytes", "bwd bytes", "total length of bwd packets", "out bytes"],
}
MIN_RESOLVED = 5


class GenericParser(BaseParser):
    @property
    def format_name(self) -> str:
        return "Generic CSV (inferred mapping)"

    def _build_rename_map(self, columns):
        normalized_lookup = {_normalize(c): c for c in columns}
        rename_map = {}
        for canonical, aliases in ALIAS_MAP.items():
            for alias in aliases:
                if alias in normalized_lookup:
                    rename_map[normalized_lookup[alias]] = canonical
                    break
        return rename_map

    def can_parse(self, file_content: bytes, filename: str) -> bool:
        try:
            df = pd.read_csv(io.BytesIO(file_content), nrows=1)
            return len(self._build_rename_map(df.columns)) >= MIN_RESOLVED
        except Exception:
            return False

    def parse(self, file_content: bytes) -> pd.DataFrame:
        df = pd.read_csv(io.BytesIO(file_content), low_memory=False)
        rename_map = self._build_rename_map(df.columns)
        if len(rename_map) < MIN_RESOLVED:
            raise ValueError(
                f"Generic parser matched only {len(rename_map)} canonical "
                f"fields (need {MIN_RESOLVED}). Columns found: {list(df.columns)}"
            )
        return df.rename(columns=rename_map)
