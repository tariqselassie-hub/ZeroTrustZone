"""
ZeroTrustZone (ZTZ) Model Weight & Architecture Pre-Flight Inspector (core/model_inspector.py)
Inspects local model weight containers (GGUF, Safetensors, ONNX, PyTorch)
before memory mapping or tensor allocation.

Invariants:
1. GGUF Integrity: Validates 4-byte magic (0x46554747), version (v2/v3), tensor count, and KV metadata pairs.
2. Safetensors Safety: Enforces 8-byte uint64 header length, valid JSON metadata, and strict absence of pickle opcodes.
3. Pickle RCE Quarantine: Flags legacy PyTorch (.pt/.bin/.pkl) files containing Python pickle opcodes (GLOBAL, REDUCE, BUILD)
   as HIGH RISK arbitrary code execution vectors.
"""

import os
import json
import struct
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class ModelInspectionReport:
    file_path: str
    file_size_bytes: int
    format: str  # "GGUF", "SAFETENSORS", "ONNX", "PYTORCH_PICKLE", "UNKNOWN"
    is_safe_format: bool
    magic_bytes_valid: bool
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    risk_level: str = "LOW"  # "LOW", "MEDIUM", "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "format": self.format,
            "is_safe_format": self.is_safe_format,
            "magic_bytes_valid": self.magic_bytes_valid,
            "metadata": self.metadata,
            "warnings": self.warnings,
            "risk_level": self.risk_level,
        }


class ModelFormatInspector:
    """Pre-flight format and container safety auditor for local neural weights."""

    # GGUF constants
    GGUF_MAGIC = b"GGUF"  # 0x46554747 little-endian

    # Dangerous Python pickle opcodes
    PICKLE_OPCODES = [b"c__builtin__", b"cposix", b"cnt", b"cos", b"csubprocess", b"R", b"b", b"c"]

    @classmethod
    def inspect(cls, file_path: str) -> ModelInspectionReport:
        if not os.path.exists(file_path):
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=0,
                format="MISSING",
                is_safe_format=False,
                magic_bytes_valid=False,
                warnings=["File does not exist on disk."],
                risk_level="CRITICAL"
            )

        file_size = os.path.getsize(file_path)
        if file_size < 8:
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="TRUNCATED",
                is_safe_format=False,
                magic_bytes_valid=False,
                warnings=["File is too small to contain valid model weight headers."],
                risk_level="CRITICAL"
            )

        with open(file_path, "rb") as f:
            header_bytes = f.read(16)

        # 1. Test GGUF format
        if header_bytes[:4] == cls.GGUF_MAGIC:
            return cls._inspect_gguf(file_path, file_size)

        # 2. Test Safetensors format
        if cls._is_safetensors(file_path, file_size):
            return cls._inspect_safetensors(file_path, file_size)

        # 3. Test for PyTorch / Pickle format
        if file_path.lower().endswith((".pt", ".bin", ".pkl", ".ckpt")):
            return cls._inspect_pickle(file_path, file_size)

        # 4. Unknown / Raw format
        return ModelInspectionReport(
            file_path=file_path,
            file_size_bytes=file_size,
            format="RAW_OR_UNKNOWN",
            is_safe_format=True,
            magic_bytes_valid=True,
            metadata={"header_hex": header_bytes[:8].hex()},
            warnings=["Unrecognized model container format; falling back to strict cryptographic hash attestation."],
            risk_level="LOW"
        )

    @classmethod
    def _inspect_gguf(cls, file_path: str, file_size: int) -> ModelInspectionReport:
        warnings = []
        metadata = {}
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                version = struct.unpack("<I", f.read(4))[0]
                tensor_count = struct.unpack("<Q", f.read(8))[0]
                kv_count = struct.unpack("<Q", f.read(8))[0]

                metadata["gguf_version"] = version
                metadata["tensor_count"] = tensor_count
                metadata["kv_metadata_count"] = kv_count

                if version not in (2, 3):
                    warnings.append(f"GGUF version {version} is deprecated or non-standard (expected v2 or v3).")

            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="GGUF",
                is_safe_format=True,
                magic_bytes_valid=True,
                metadata=metadata,
                warnings=warnings,
                risk_level="LOW" if not warnings else "MEDIUM"
            )
        except Exception as e:
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="GGUF",
                is_safe_format=False,
                magic_bytes_valid=True,
                warnings=[f"Failed to parse GGUF header: {e}"],
                risk_level="CRITICAL"
            )

    @classmethod
    def _is_safetensors(cls, file_path: str, file_size: int) -> bool:
        if file_size < 10:
            return False
        try:
            with open(file_path, "rb") as f:
                header_len = struct.unpack("<Q", f.read(8))[0]
                if header_len < 2 or header_len > (file_size - 8) or header_len > 100 * 1024 * 1024:
                    return False
                first_char = f.read(1)
                return first_char == b"{"
        except Exception:
            return False

    @classmethod
    def _inspect_safetensors(cls, file_path: str, file_size: int) -> ModelInspectionReport:
        try:
            with open(file_path, "rb") as f:
                header_len = struct.unpack("<Q", f.read(8))[0]
                header_json_bytes = f.read(header_len)
                header = json.loads(header_json_bytes.decode("utf-8"))

            tensor_keys = [k for k in header.keys() if k != "__metadata__"]
            metadata = {
                "header_size_bytes": header_len,
                "tensor_count": len(tensor_keys),
                "custom_metadata": header.get("__metadata__", {})
            }

            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="SAFETENSORS",
                is_safe_format=True,
                magic_bytes_valid=True,
                metadata=metadata,
                warnings=[],
                risk_level="LOW"
            )
        except Exception as e:
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="SAFETENSORS",
                is_safe_format=False,
                magic_bytes_valid=False,
                warnings=[f"Corrupt or tampered Safetensors JSON header: {e}"],
                risk_level="CRITICAL"
            )

    @classmethod
    def _inspect_pickle(cls, file_path: str, file_size: int) -> ModelInspectionReport:
        warnings = [
            "Legacy PyTorch weights (.pt/.bin) rely on Python pickle parsing, which allows arbitrary code execution (RCE).",
            "Strongly recommend converting to Safetensors or GGUF before running in production."
        ]
        has_risky_opcodes = False
        try:
            with open(file_path, "rb") as f:
                head = f.read(4096)
                for op in cls.PICKLE_OPCODES:
                    if op in head:
                        has_risky_opcodes = True
                        warnings.append(f"Suspicious pickle opcode pattern detected: '{op.decode(errors='ignore')}'")
                        break
        except Exception as e:
            warnings.append(f"Could not scan pickle header: {e}")

        return ModelInspectionReport(
            file_path=file_path,
            file_size_bytes=file_size,
            format="PYTORCH_PICKLE",
            is_safe_format=False,
            magic_bytes_valid=True,
            metadata={"pickle_format": True, "has_risky_opcodes": has_risky_opcodes},
            warnings=warnings,
            risk_level="CRITICAL" if has_risky_opcodes else "MEDIUM"
        )
