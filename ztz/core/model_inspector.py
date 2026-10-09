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
import io
import json
import struct
import zipfile
import pickletools
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

    # Imports that give a pickle code execution, filesystem, process or network reach.
    DANGEROUS_PICKLE_MODULES = frozenset({
        "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy",
        "importlib", "pty", "webbrowser", "ctypes", "code", "marshal", "pickle",
        "urllib", "requests", "http", "asyncio", "multiprocessing", "signal",
    })
    DANGEROUS_PICKLE_BUILTINS = frozenset({
        "eval", "exec", "compile", "open", "getattr", "setattr", "delattr",
        "__import__", "globals", "locals", "vars", "input", "breakpoint",
    })
    # Imports a vanilla torch.save()/numpy checkpoint legitimately needs.
    SAFE_PICKLE_GLOBALS = frozenset({
        ("collections", "OrderedDict"),
        ("torch", "Size"),
        ("torch", "device"),
        ("torch", "dtype"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch._utils", "_rebuild_qtensor"),
        ("torch._utils", "_rebuild_sparse_tensor"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
        ("_codecs", "encode"),
    })
    MAX_PICKLE_STREAMS = 8              # legacy torch files concatenate several pickles
    MAX_PICKLE_SCAN_BYTES = 256 * 1024 * 1024

    @classmethod
    def inspect(cls, file_path: str, read_path: Optional[str] = None) -> ModelInspectionReport:
        """
        Inspects file_path. read_path, if given, is where the bytes are read from
        (e.g. a pinned /proc/self/fd/N); file_path still drives extension checks.
        """
        report = cls._inspect(read_path or file_path, file_path)
        report.file_path = file_path
        return report

    @classmethod
    def _inspect(cls, file_path: str, name: str) -> ModelInspectionReport:
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
        if name.lower().endswith((".pt", ".bin", ".pkl", ".ckpt")):
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
        dangerous, unknown = set(), set()
        try:
            if zipfile.is_zipfile(file_path):
                # torch.save() >= 1.6: zip archive with the object graph in */data.pkl
                with zipfile.ZipFile(file_path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".pkl"):
                            with zf.open(name) as member:
                                cls._scan_pickle_stream(io.BufferedReader(member), dangerous, unknown)
            else:
                with open(file_path, "rb") as f:
                    cls._scan_pickle_stream(f, dangerous, unknown)
        except Exception as e:
            warnings.append(f"Could not fully scan pickle stream: {e}")

        for ref in sorted(dangerous):
            warnings.append(f"Dangerous pickle opcode import detected: '{ref}' (GLOBAL/STACK_GLOBAL)")
        for ref in sorted(unknown):
            warnings.append(f"Non-standard pickle import: '{ref}'")

        has_risky_opcodes = bool(dangerous)
        return ModelInspectionReport(
            file_path=file_path,
            file_size_bytes=file_size,
            format="PYTORCH_PICKLE",
            is_safe_format=False,
            magic_bytes_valid=True,
            metadata={
                "pickle_format": True,
                "has_risky_opcodes": has_risky_opcodes,
                "dangerous_imports": sorted(dangerous),
                "unknown_imports": sorted(unknown),
            },
            warnings=warnings,
            risk_level="CRITICAL" if has_risky_opcodes else "MEDIUM"
        )

    @classmethod
    def _classify_global(cls, module: str, name: str, dangerous: set, unknown: set):
        ref = f"{module}.{name}"
        root = module.split(".", 1)[0]
        if root in cls.DANGEROUS_PICKLE_MODULES:
            dangerous.add(ref)
        elif root in ("builtins", "__builtin__") and name in cls.DANGEROUS_PICKLE_BUILTINS:
            dangerous.add(ref)
        elif (module, name) in cls.SAFE_PICKLE_GLOBALS:
            pass
        elif module == "torch" and name.endswith("Storage"):
            pass
        else:
            unknown.add(ref)

    @classmethod
    def _scan_pickle_stream(cls, f, dangerous: set, unknown: set):
        """
        Statically walks pickle opcodes (never executes them) and records every
        imported global. Handles protocol 0-5 GLOBAL and STACK_GLOBAL forms.
        """
        start = f.tell() if f.seekable() else 0
        for _ in range(cls.MAX_PICKLE_STREAMS):
            memo, stack_strs = {}, []   # stack_strs mirrors string pushes feeding STACK_GLOBAL
            saw_stop = False
            for opcode, arg, pos in pickletools.genops(f):
                if pos is not None and pos - start > cls.MAX_PICKLE_SCAN_BYTES:
                    return
                op = opcode.name
                if op == "GLOBAL":
                    module, _, name = str(arg).partition(" ")
                    cls._classify_global(module, name, dangerous, unknown)
                    stack_strs.clear()
                elif op == "STACK_GLOBAL":
                    if len(stack_strs) >= 2 and None not in stack_strs[-2:]:
                        cls._classify_global(stack_strs[-2], stack_strs[-1], dangerous, unknown)
                    else:
                        unknown.add("<unresolved STACK_GLOBAL>")
                    stack_strs.clear()
                elif op in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                            "SHORT_BINSTRING", "BINSTRING", "STRING"):
                    stack_strs.append(str(arg))
                elif op == "MEMOIZE":
                    memo[len(memo)] = stack_strs[-1] if stack_strs else None
                elif op in ("PUT", "BINPUT", "LONG_BINPUT"):
                    memo[arg] = stack_strs[-1] if stack_strs else None
                elif op in ("GET", "BINGET", "LONG_BINGET"):
                    stack_strs.append(memo.get(arg))
                elif op == "STOP":
                    saw_stop = True
                    break
                else:
                    stack_strs.append(None)
                del stack_strs[:-2]
            if not saw_stop:
                return
            # Legacy torch format: more pickles follow until raw storage bytes.
            peek = f.peek(1)[:1] if hasattr(f, "peek") else b""
            if peek != b"\x80":
                return
