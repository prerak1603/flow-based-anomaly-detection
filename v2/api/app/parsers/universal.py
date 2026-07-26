"""
Universal parser - detects format and dispatches to correct parser.
"""

import pandas as pd
from typing import Tuple

from app.parsers.cicflow_parser import CICFlowParser
from app.parsers.zeek_parser import ZeekParser
from app.parsers.generic_parser import GenericParser


class UniversalParser:
    """
    Detects log format and parses using appropriate parser.
    
    Tries each registered parser in order, using the first
    one that successfully identifies the format.
    """
    
    def __init__(self):
        # Order matters - more specific parsers first
        self.parsers = [
            CICFlowParser(),
            ZeekParser(),
            GenericParser(),  # fallback - least specific, must go last
        ]
    
    def parse(self, file_content: bytes, filename: str) -> Tuple[pd.DataFrame, str]:
        """
        Parse file content, auto-detecting format.
        
        Args:
            file_content: Raw bytes of uploaded file
            filename: Original filename (helps with detection)
        
        Returns:
            Tuple of (parsed DataFrame, detected format name)
        
        Raises:
            ValueError: If no parser can handle the file
        """
        for parser in self.parsers:
            if parser.can_parse(file_content, filename):
                df = parser.parse(file_content)
                return df, parser.format_name
        
        raise ValueError(
            f"Could not detect format for file: {filename}. "
            f"Supported formats: "
            f"{', '.join(p.format_name for p in self.parsers)}"
        )
    
    def list_supported_formats(self) -> list:
        """Return list of supported format names."""
        return [p.format_name for p in self.parsers]