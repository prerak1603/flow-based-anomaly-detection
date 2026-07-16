"""
Parser for Zeek (formerly Bro) conn.log files.
Zeek is the industry-standard network monitoring tool.
"""

import pandas as pd
import io
from app.parsers.base import BaseParser


class ZeekParser(BaseParser):
    """
    Parses Zeek conn.log format.
    
    Zeek logs are tab-separated with a specific header 
    format starting with #fields.
    """
    
    @property
    def format_name(self) -> str:
        return "Zeek conn.log"
    
    def can_parse(self, file_content: bytes, filename: str) -> bool:
        """Zeek logs start with #separator and #fields lines."""
        try:
            text = file_content.decode('utf-8', errors='ignore')
            first_lines = text.split('\n')[:10]
            return any('#fields' in line for line in first_lines)
        except Exception:
            return False
    
    def parse(self, file_content: bytes) -> pd.DataFrame:
        """
        Parse Zeek conn.log and map to basic flow features.
        
        Zeek's raw columns differ from CICFlowMeter, so we
        extract what's available and let the feature 
        extractor fill gaps.
        """
        text = file_content.decode('utf-8', errors='ignore')
        lines = text.split('\n')
        
        # Find the #fields line to get column names
        field_line = next(
            (l for l in lines if l.startswith('#fields')), 
            None
        )
        
        if not field_line:
            raise ValueError("Could not find #fields header in Zeek log")
        
        columns = field_line.replace('#fields', '').strip().split('\t')
        
        # Get data lines (skip comments starting with #)
        data_lines = [l for l in lines if l and not l.startswith('#')]
        
        # Parse into DataFrame
        data = [line.split('\t') for line in data_lines]
        df = pd.DataFrame(data, columns=columns)
        
        return df