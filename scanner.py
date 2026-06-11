import os
import re
import hashlib
import math
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    engine: str
    severity: Severity
    title: str
    description: str
    detail: str = ""


@dataclass
class ScanResult:
    path: str
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    findings: list = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max((f.severity for f in self.findings), key=lambda s: order.index(s))

    @property
    def is_suspicious(self) -> bool:
        return self.max_severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


YARA_RULES = [
    {
        "name": "Encoded PowerShell command",
        "pattern": re.compile(rb"powershell\s+-[ecn]", re.I),
        "severity": Severity.HIGH,
        "description": "PowerShell with encoded command flag"
    },
    {
        "name": "Suspicious PowerShell -WindowStyle",
        "pattern": re.compile(rb"-windowstyle\s+hidden", re.I),
        "severity": Severity.HIGH,
        "description": "PowerShell hidden window execution"
    },
    {
        "name": "Large base64 blob",
        "pattern": re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}"),
        "severity": Severity.MEDIUM,
        "description": "Large base64-encoded blob (possible payload)"
    },
    {
        "name": "WinExec/ShellExecute call",
        "pattern": re.compile(rb"\b(winexec|shellexecute[a-w]?)\s*\(", re.I),
        "severity": Severity.HIGH,
        "description": "Direct process execution API call"
    },
    {
        "name": "Embedded PE executable",
        "pattern": re.compile(b"MZ\x90\x00"),
        "severity": Severity.HIGH,
        "description": "Embedded PE header detected in file"
    },
    {
        "name": "JavaScript eval with decode",
        "pattern": re.compile(rb"eval\s*\(\s*(atob|decode|unescape)", re.I),
        "severity": Severity.MEDIUM,
        "description": "JavaScript eval used with deobfuscation function"
    },
    {
        "name": "Hardcoded IP address URL",
        "pattern": re.compile(rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
        "severity": Severity.MEDIUM,
        "description": "URL with hardcoded IP address"
    },
    {
        "name": "Suspicious VBA auto-exec macro",
        "pattern": re.compile(rb"(autoopen|autoexec|document_open)\s*\(", re.I),
        "severity": Severity.HIGH,
        "description": "VBA auto-executing macro detected"
    },
]

KNOWN_MALWARE_HASHES = set()


class ScannerEngine:
    def scan_file(self, path: str, progress_callback=None) -> ScanResult:
        stat = os.stat(path)
        data = open(path, "rb").read()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        result = ScanResult(
            path=path,
            filename=os.path.basename(path),
            size=stat.st_size,
            md5=md5, sha1=sha1, sha256=sha256
        )

        self._check_hash(result)
        self._check_yara_patterns(data, result)
        self._check_entropy(data, result)

        if HAS_PEFILE and (data[:2] == b"MZ"):
            self._check_pe(data, result)

        self._check_heuristics(path, data, result)

        return result

    def _check_hash(self, result: ScanResult):
        if result.md5 in KNOWN_MALWARE_HASHES or result.sha1 in KNOWN_MALWARE_HASHES:
            result.findings.append(Finding(
                engine="Hash Lookup", severity=Severity.CRITICAL,
                title="Known malware hash match",
                description=f"File hash matches known malicious sample"
            ))

    def _check_yara_patterns(self, data: bytes, result: ScanResult):
        is_pe = data[:2] == b"MZ"
        for rule in YARA_RULES:
            try:
                if isinstance(rule["pattern"], re.Pattern):
                    if is_pe and rule["name"] == "Embedded PE executable":
                        match = rule["pattern"].search(data, 2)
                    else:
                        match = rule["pattern"].search(data)
                    if match:
                        result.findings.append(Finding(
                            engine="Sig Scanner", severity=rule["severity"],
                            title=rule["name"],
                            description=rule["description"]
                        ))
                elif isinstance(rule["pattern"], bytes):
                    if rule["pattern"] in data:
                        result.findings.append(Finding(
                            engine="Sig Scanner", severity=rule["severity"],
                            title=rule["name"],
                            description=rule["description"]
                        ))
            except Exception:
                pass

    def _check_entropy(self, data: bytes, result: ScanResult):
        if len(data) < 64:
            return
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq if c > 0)

        if entropy > 7.5:
            result.findings.append(Finding(
                engine="Entropy", severity=Severity.HIGH,
                title="High entropy (packed/encrypted)",
                description=f"Entropy score: {entropy:.2f} (threshold: 7.5) — likely packed or encrypted"
            ))
        elif entropy > 7.0:
            result.findings.append(Finding(
                engine="Entropy", severity=Severity.MEDIUM,
                title="Elevated entropy",
                description=f"Entropy score: {entropy:.2f} (threshold: 7.0)"
            ))

    def _check_pe(self, data: bytes, result: ScanResult):
        try:
            pe = pefile.PE(data=data)
        except Exception:
            return

        suspicious_sections = [b".UPX", b".pack", b".aspack", b".upx!", b"UPX0", b"UPX1"]
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00")
            if any(p in name for p in suspicious_sections):
                section_name = name.decode("latin-1", errors="replace")
                result.findings.append(Finding(
                    engine="PE Analyzer", severity=Severity.HIGH,
                    title=f"Suspicious section: {section_name}",
                    description=f"Packer/compressor section detected: {section_name}"
                ))
            if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                result.findings.append(Finding(
                    engine="PE Analyzer", severity=Severity.MEDIUM,
                    title=f"Section {name.decode('latin-1', errors='replace')} has no raw data",
                    description="Section with virtual size but zero raw data (common in packed files)"
                ))

        high_risk = {"CreateRemoteThread", "WriteProcessMemory", "WinExec", "ShellExecuteA",
                      "SetWindowsHookEx", "ResumeThread"}
        medium_risk = {"VirtualAlloc", "VirtualProtect", "GetProcAddress", "LoadLibraryA",
                        "LoadLibraryExW"}
        suspicious_imports = []
        high_risk_found = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("latin-1", errors="replace").lower()
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("latin-1", errors="replace")
                        dll = dll_name.replace(".dll", "")
                        if name in high_risk:
                            high_risk_found.append(f"{dll}!{name}")
                        elif name in medium_risk:
                            suspicious_imports.append(f"{dll}!{name}")

        if high_risk_found:
            result.findings.append(Finding(
                engine="PE Analyzer", severity=Severity.HIGH,
                title=f"High-risk imports ({len(high_risk_found)})",
                description="; ".join(high_risk_found[:8])
            ))
        if len(suspicious_imports) >= 3:
            result.findings.append(Finding(
                engine="PE Analyzer", severity=Severity.MEDIUM,
                title=f"Suspicious imports ({len(suspicious_imports)})",
                description="; ".join(suspicious_imports[:8])
            ))

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            try:
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(res_type, "struct") and res_type.struct.Id == 10:
                        result.findings.append(Finding(
                            engine="PE Analyzer", severity=Severity.MEDIUM,
                            title="RT_RCDATA resource present",
                            description="Binary resource data often used for payload storage"
                        ))
            except Exception:
                pass

    def _check_heuristics(self, path: str, data: bytes, result: ScanResult):
        ext = Path(path).suffix.lower()

        if ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"):
            if b"AutoOpen" in data or b"Document_Open" in data or b"VBA" in data:
                result.findings.append(Finding(
                    engine="Doc Scanner", severity=Severity.HIGH,
                    title="Document with macros",
                    description="Document contains VBA macros — potential malware vector"
                ))

        if ext == ".js":
            suspicious_js = [b"WScript.Shell", b"ActiveXObject", b"new ActiveX", b"Shell.Application"]
            matches = [s.decode() for s in suspicious_js if s in data]
            if matches:
                result.findings.append(Finding(
                    engine="JS Scanner", severity=Severity.MEDIUM,
                    title="Suspicious JavaScript APIs",
                    description=", ".join(matches)
                ))

        if ext == ".ps1":
            suspicious_ps = [b"-e ", b"-enc ", b"-windowstyle hidden", b"IEX(", b"Invoke-Expression"]
            matches = [s.decode() for s in suspicious_ps if s in data]
            if matches:
                result.findings.append(Finding(
                    engine="PS Scanner", severity=Severity.HIGH,
                    title="Suspicious PowerShell script",
                    description=", ".join(matches)
                ))

        null_ratio = data.count(b"\x00") / len(data) if data else 0
        if null_ratio > 0.3:
            result.findings.append(Finding(
                engine="Heuristic", severity=Severity.MEDIUM,
                title="High null-byte ratio",
                description=f"{null_ratio:.1%} null bytes — possibly obfuscated or sparse"
            ))

        interesting_strings = re.findall(rb"https?://[^\s\"'<>]{10,200}", data)
        suspicious_urls = [u for u in interesting_strings if not any(
            safe in u for safe in [b"google.com", b"microsoft.com", b"windows.com", 
                                    b"github.com", b"python.org"])]
        if suspicious_urls:
            result.findings.append(Finding(
                engine="Heuristic", severity=Severity.LOW,
                title=f"Suspicious URLs ({len(suspicious_urls)})",
                description=suspicious_urls[0][:120].decode("latin-1", errors="replace")
            ))


class BatchScanner:
    def __init__(self, engine: ScannerEngine, max_workers: int = 4):
        self.engine = engine
        self.max_workers = max_workers
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def scan_paths(self, paths: list, progress_callback=None) -> list:
        self._cancelled = False
        files = []
        for path in paths:
            if os.path.isfile(path):
                files.append(path)
            elif os.path.isdir(path):
                for root, _, filenames in os.walk(path):
                    for f in filenames:
                        files.append(os.path.join(root, f))
                        if self._cancelled:
                            return []

        results = []
        total = len(files)
        completed = 0

        skip_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".mp3", ".mp4",
                           ".wav", ".avi", ".mkv", ".mov", ".flac", ".ogg", ".webm",
                           ".ttf", ".otf", ".woff", ".woff2", ".eot", ".cur"}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for f in files:
                ext = Path(f).suffix.lower()
                if ext in skip_extensions:
                    completed += 1
                    continue
                if os.path.getsize(f) < 5:
                    completed += 1
                    continue
                futures[executor.submit(self.engine.scan_file, f)] = f

            for future in as_completed(futures):
                if self._cancelled:
                    executor.shutdown(wait=False)
                    return results
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, futures[future])
                try:
                    results.append(future.result())
                except Exception:
                    pass

        return results
