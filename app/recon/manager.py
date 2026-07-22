from __future__ import annotations
import asyncio
from typing import List, Dict, Optional
from app.models.schemas import RawFinding, ScannerModule
from app.recon.base import BaseScanner
from app.recon.dns_scanner import DNSScanner
from app.recon.port_scanner import PortScanner
from app.recon.web_scanner import WebScanner


class ReconManager:
    """Orchestrates asynchronous execution of attack surface scanners."""

    def __init__(self):
        self.scanners: Dict[ScannerModule, BaseScanner] = {
            ScannerModule.DNS: DNSScanner(),
            ScannerModule.PORT: PortScanner(),
            ScannerModule.WEB_HEADERS: WebScanner(),
        }

    async def run_scan(self, target: str, modules_to_run: Optional[List[ScannerModule]] = None) -> List[RawFinding]:
        """Run requested reconnaissance modules in parallel and return aggregated raw findings."""
        if not modules_to_run:
            modules_to_run = list(self.scanners.keys())

        active_scanners = [
            self.scanners[mod] for mod in modules_to_run if mod in self.scanners
        ]

        if not active_scanners:
            return []

        # Execute all active scanners concurrently using asyncio.gather
        tasks = [scanner.scan(target) for scanner in active_scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        aggregated_findings: List[RawFinding] = []
        for res in results:
            if isinstance(res, list):
                aggregated_findings.extend(res)
            elif isinstance(res, Exception):
                # Log exception but do not abort overall scan
                print(f"[WARN] Scanner module threw exception: {res}")

        return aggregated_findings


recon_manager = ReconManager()
