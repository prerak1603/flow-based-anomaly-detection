"""
Base parser interface.
All specific parsers inherit from this.
"""

from abc import ABC, abstractmethod
import pandas as pd
from typing import List


class BaseParser(ABC):
    """Abstract base class for log parsers."""
    
    @abstractmethod
    def can_parse(self, file_content: bytes, filename: str) -> bool:
        """Check if this parser can handle the given file."""
        pass
    
    @abstractmethod
    def parse(self, file_content: bytes) -> pd.DataFrame:
        """Parse file content into a DataFrame."""
        pass
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Human-readable name of this format."""
        pass