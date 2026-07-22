from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List
from app.models.schemas import RawFinding, ScannerModule


class BaseScanner(ABC):
    """Abstract base class for all attack surface reconnaissance modules."""

    @property
    @abstractmethod
    def module_name(self) -> ScannerModule:
        """Return the ScannerModule enum for this scanner."""
        pass

    @abstractmethod
    async def scan(self, target: str) -> List[RawFinding]:
        """Run the reconnaissance module against the specified target and return raw findings."""
        pass
