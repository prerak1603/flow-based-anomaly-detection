"""
Parser for CICFlowMeter-style CSV output.
This is the SAME format as our training data (CIC-IDS-2017).
"""

import pandas as pd
import io
from app.parsers.base import BaseParser


class CICFlowParser(BaseParser):
    """
    Parses CICFlowMeter CSV output.
    
    This is the gold-standard format since it matches 
    exactly what our model was trained on.
    """
    
    # Expected column names (subset for detection)
    SIGNATURE_COLUMNS = [
        'Flow Duration', 'Total Fwd Packets', 
        'Total Backward Packets', 'Destination Port'
    ]
    
    @property
    def format_name(self) -> str:
        return "CICFlowMeter CSV"
    
    def can_parse(self, file_content: bytes, filename: str) -> bool:
        """Check if columns match CICFlowMeter signature."""
        try:
            df = pd.read_csv(io.BytesIO(file_content), nrows=1)
            df.columns = df.columns.str.strip()
            
            matches = sum(
                1 for col in self.SIGNATURE_COLUMNS 
                if col in df.columns
            )
            return matches >= 3
        except Exception:
            return False
    
    def parse(self, file_content: bytes) -> pd.DataFrame:
        """Parse CICFlowMeter CSV directly."""
        df = pd.read_csv(io.BytesIO(file_content), low_memory=False)
        df.columns = df.columns.str.strip()
        
        # Drop label column if present (this is client data, no labels)
        if 'Label' in df.columns:
            df = df.drop(columns=['Label'])
        
        return df