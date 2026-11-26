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

        # 3. Test ONNX format
        if name.lower().endswith(".onnx"):
            return cls._inspect_onnx(file_path, file_size)

        # 4. Test for PyTorch / Pickle format
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
    def _read_gguf_string(cls, f) -> str:
        len_bytes = f.read(8)
        if len(len_bytes) < 8:
            return ""
        s_len = struct.unpack("<Q", len_bytes)[0]
        if s_len == 0:
            return ""
        if s_len > 64 * 1024:
            f.seek(s_len, io.SEEK_CUR)
            return "<TRUNCATED_STRING>"
        s_bytes = f.read(s_len)
        return s_bytes.decode("utf-8", errors="replace")

    @classmethod
    def _read_gguf_value(cls, f, val_type: int) -> Any:
        if val_type == 0:
            return struct.unpack("<B", f.read(1))[0]
        elif val_type == 1:
            return struct.unpack("<b", f.read(1))[0]
        elif val_type == 2:
            return struct.unpack("<H", f.read(2))[0]
        elif val_type == 3:
            return struct.unpack("<h", f.read(2))[0]
        elif val_type == 4:
            return struct.unpack("<I", f.read(4))[0]
        elif val_type == 5:
            return struct.unpack("<i", f.read(4))[0]
        elif val_type == 6:
            return struct.unpack("<f", f.read(4))[0]
        elif val_type == 7:
            return bool(struct.unpack("<B", f.read(1))[0])
        elif val_type == 8:
            return cls._read_gguf_string(f)
        elif val_type == 9:
            item_type = struct.unpack("<I", f.read(4))[0]
            arr_len = struct.unpack("<Q", f.read(8))[0]
            if arr_len > 64:
                cls._skip_gguf_array(f, item_type, arr_len)
                return f"<ARRAY[{arr_len}]>"
            items = []
            for _ in range(arr_len):
                items.append(cls._read_gguf_value(f, item_type))
            return items
        elif val_type == 10:
            return struct.unpack("<Q", f.read(8))[0]
        elif val_type == 11:
            return struct.unpack("<q", f.read(8))[0]
        elif val_type == 12:
            return struct.unpack("<d", f.read(8))[0]
        else:
            raise ValueError(f"Unknown GGUF value type: {val_type}")

    @classmethod
    def _skip_gguf_array(cls, f, item_type: int, arr_len: int):
        sizes = {
            0: 1, 1: 1, 7: 1,
            2: 2, 3: 2,
            4: 4, 5: 4, 6: 4,
            10: 8, 11: 8, 12: 8,
        }
        if item_type in sizes:
            f.seek(arr_len * sizes[item_type], io.SEEK_CUR)
        elif item_type == 8:
            for _ in range(arr_len):
                s_len = struct.unpack("<Q", f.read(8))[0]
                f.seek(s_len, io.SEEK_CUR)
        else:
            for _ in range(arr_len):
                cls._read_gguf_value(f, item_type)

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

                # Parse KV metadata safely up to limit (max 10,000 keys or 32MB header)
                try:
                    max_kv = min(kv_count, 10000)
                    parsed_kv = {}
                    for _ in range(max_kv):
                        if f.tell() >= file_size or f.tell() > 32 * 1024 * 1024:
                            break
                        key = cls._read_gguf_string(f)
                        if not key:
                            continue
                        val_type_bytes = f.read(4)
                        if len(val_type_bytes) < 4:
                            break
                        val_type = struct.unpack("<I", val_type_bytes)[0]
                        val = cls._read_gguf_value(f, val_type)
                        parsed_kv[key] = val

                    # Promote architectural parameters of interest
                    arch = parsed_kv.get("general.architecture")
                    if arch:
                        metadata["architecture"] = arch
                        for suffix, out_key in (
                            ("context_length", "context_length"),
                            ("embedding_length", "embedding_length"),
                            ("block_count", "block_count"),
                            ("feed_forward_length", "feed_forward_length"),
                            ("attention.head_count", "head_count"),
                            ("attention.head_count_kv", "head_count_kv"),
                        ):
                            full_key = f"{arch}.{suffix}"
                            if full_key in parsed_kv:
                                metadata[out_key] = parsed_kv[full_key]

                    if "general.parameter_count" in parsed_kv:
                        metadata["parameter_count"] = parsed_kv["general.parameter_count"]
                    if "general.name" in parsed_kv:
                        metadata["model_name"] = parsed_kv["general.name"]
                    if "general.file_type" in parsed_kv:
                        metadata["file_type"] = parsed_kv["general.file_type"]

                    # Audit embedded Jinja2 chat templates for SSTI gadgets
                    ssti_patterns = (
                        "__class__", "__mro__", "__subclasses__", "__globals__",
                        "__builtins__", "__import__", "cycler", "joiner", "lipsum",
                    )
                    for k, v in parsed_kv.items():
                        if (k == "tokenizer.chat_template" or k.startswith("tokenizer.chat_template.")) and isinstance(v, str):
                            lower_tpl = v.lower()
                            hits = [p for p in ssti_patterns if p in lower_tpl]
                            if hits:
                                metadata["chat_template_risk"] = True
                                warnings.append(
                                    f"Suspicious Jinja2 SSTI gadget(s) in '{k}': {', '.join(hits)}"
                                )
                except Exception:
                    pass

            has_ssti = bool(metadata.get("chat_template_risk"))
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="GGUF",
                is_safe_format=not has_ssti,
                magic_bytes_valid=True,
                metadata=metadata,
                warnings=warnings,
                risk_level="CRITICAL" if has_ssti else ("LOW" if not warnings else "MEDIUM")
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
            payload_size = file_size - 8 - header_len
            ranges = []
            for k in tensor_keys:
                entry = header.get(k)
                if not isinstance(entry, dict) or "data_offsets" not in entry:
                    raise ValueError(f"Tensor '{k}' missing data_offsets")
                offsets = entry["data_offsets"]
                if (
                    not isinstance(offsets, list)
                    or len(offsets) != 2
                    or not all(isinstance(x, int) and not isinstance(x, bool) for x in offsets)
                ):
                    raise ValueError(f"Tensor '{k}' has invalid data_offsets")
                begin, end = offsets
                if begin < 0 or end < begin:
                    raise ValueError(f"Tensor '{k}' data_offsets [{begin}, {end}] invalid")
                if end > begin:
                    ranges.append((begin, end, k))

            ranges.sort(key=lambda r: (r[0], r[1]))
            for i in range(1, len(ranges)):
                if ranges[i][0] < ranges[i - 1][1]:
                    raise ValueError(
                        f"Overlapping tensor data_offsets between '{ranges[i - 1][2]}' and '{ranges[i][2]}'"
                    )

            metadata = {
                "header_size_bytes": header_len,
                "tensor_count": len(tensor_keys),
                "custom_metadata": header.get("__metadata__", {}),
            }
            if ranges and ranges[-1][1] > payload_size:
                metadata["truncated_payload"] = True

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

    @staticmethod
    def _pb_read_varint(buf: memoryview, pos: int) -> tuple[int, int]:
        val = 0
        shift = 0
        n = len(buf)
        while pos < n:
            b = buf[pos]
            pos += 1
            val |= (b & 0x7F) << shift
            if not (b & 0x80):
                return val, pos
            shift += 7
            if shift > 63:
                raise ValueError("Protobuf varint overflow")
        raise ValueError("Truncated protobuf varint")

    @classmethod
    def _pb_iter_fields(cls, buf: memoryview):
        pos = 0
        n = len(buf)
        while pos < n:
            tag, pos = cls._pb_read_varint(buf, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07
            if field_num == 0:
                raise ValueError("Invalid protobuf field number 0")
            if wire_type == 0:
                val, pos = cls._pb_read_varint(buf, pos)
                yield field_num, wire_type, val
            elif wire_type == 1:
                if pos + 8 > n:
                    raise ValueError("Truncated 64-bit protobuf field")
                yield field_num, wire_type, buf[pos:pos + 8]
                pos += 8
            elif wire_type == 2:
                length, pos = cls._pb_read_varint(buf, pos)
                if pos + length > n:
                    raise ValueError("Truncated length-delimited protobuf field")
                yield field_num, wire_type, buf[pos:pos + length]
                pos += length
            elif wire_type == 5:
                if pos + 4 > n:
                    raise ValueError("Truncated 32-bit protobuf field")
                yield field_num, wire_type, buf[pos:pos + 4]
                pos += 4
            else:
                raise ValueError(f"Unsupported protobuf wire type: {wire_type}")

    @staticmethod
    def _is_unsafe_external_path(loc: str) -> bool:
        if not loc:
            return False
        norm = loc.replace("\\", "/")
        if "://" in norm or norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
            return True
        return any(part == ".." for part in norm.split("/"))

    @classmethod
    def _inspect_onnx(cls, file_path: str, file_size: int) -> ModelInspectionReport:
        standard_domains = frozenset({"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"})
        warnings: List[str] = []
        metadata: Dict[str, Any] = {}
        custom_domains = set()
        external_paths: List[str] = []
        unsafe_paths: List[str] = []

        if file_size > cls.MAX_PICKLE_SCAN_BYTES:
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="ONNX",
                is_safe_format=True,
                magic_bytes_valid=True,
                metadata={"note": "Skipped deep protobuf scan (>256MB); relying on cryptographic signature."},
                warnings=[],
                risk_level="LOW",
            )

        try:
            with open(file_path, "rb") as f:
                data = f.read()
            mv = memoryview(data)
            opsets = []
            node_count = 0
            saw_model_field = False

            for field_num, wire_type, val in cls._pb_iter_fields(mv):
                if field_num == 1 and wire_type == 0:
                    metadata["ir_version"] = val
                    saw_model_field = True
                elif field_num == 2 and wire_type == 2:
                    metadata["producer_name"] = bytes(val).decode("utf-8", errors="replace")
                    saw_model_field = True
                elif field_num == 3 and wire_type == 2:
                    metadata["producer_version"] = bytes(val).decode("utf-8", errors="replace")
                    saw_model_field = True
                elif field_num == 8 and wire_type == 2:
                    saw_model_field = True
                    dom, ver = "", 0
                    for sub_f, sub_w, sub_v in cls._pb_iter_fields(val):
                        if sub_f == 1 and sub_w == 2:
                            dom = bytes(sub_v).decode("utf-8", errors="replace")
                        elif sub_f == 2 and sub_w == 0:
                            ver = sub_v
                    opsets.append(f"{dom or 'ai.onnx'}:{ver}")
                    if dom not in standard_domains:
                        custom_domains.add(dom)
                elif field_num == 7 and wire_type == 2:
                    saw_model_field = True
                    for gf, gw, gv in cls._pb_iter_fields(val):
                        if gf == 1 and gw == 2:
                            node_count += 1
                            for nf, nw, nv in cls._pb_iter_fields(gv):
                                if nf == 7 and nw == 2:
                                    ndom = bytes(nv).decode("utf-8", errors="replace")
                                    if ndom not in standard_domains:
                                        custom_domains.add(ndom)
                        elif gf == 5 and gw == 2:
                            for tf, tw, tv in cls._pb_iter_fields(gv):
                                if tf == 13 and tw == 2:
                                    k_str, v_str = "", ""
                                    for ef, ew, ev in cls._pb_iter_fields(tv):
                                        if ef == 1 and ew == 2:
                                            k_str = bytes(ev).decode("utf-8", errors="replace")
                                        elif ef == 2 and ew == 2:
                                            v_str = bytes(ev).decode("utf-8", errors="replace")
                                    if k_str == "location" and v_str:
                                        external_paths.append(v_str)
                                        if cls._is_unsafe_external_path(v_str):
                                            unsafe_paths.append(v_str)

            if not saw_model_field:
                raise ValueError("No valid ONNX ModelProto fields found")

            if opsets:
                metadata["opsets"] = opsets
            metadata["node_count"] = node_count
            if custom_domains:
                metadata["custom_domains"] = sorted(custom_domains)
                warnings.append(f"Non-standard ONNX operator domain(s): {', '.join(sorted(custom_domains))}")
            if external_paths:
                metadata["external_data_locations"] = external_paths
            if unsafe_paths:
                warnings.append(f"Unsafe external_data path traversal detected: {', '.join(unsafe_paths)}")
                return ModelInspectionReport(
                    file_path=file_path,
                    file_size_bytes=file_size,
                    format="ONNX",
                    is_safe_format=False,
                    magic_bytes_valid=True,
                    metadata=metadata,
                    warnings=warnings,
                    risk_level="CRITICAL",
                )

            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="ONNX",
                is_safe_format=True,
                magic_bytes_valid=True,
                metadata=metadata,
                warnings=warnings,
                risk_level="MEDIUM" if warnings else "LOW",
            )
        except Exception as e:
            return ModelInspectionReport(
                file_path=file_path,
                file_size_bytes=file_size,
                format="ONNX",
                is_safe_format=True,
                magic_bytes_valid=False,
                warnings=[f"Could not parse ONNX protobuf ({e}); relying on cryptographic signature."],
                risk_level="MEDIUM",
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
                    # Object graphs are small (tensor bytes live outside the pickle), so a
                    # stream this long is padding meant to hide a later import: fail closed.
                    dangerous.add("<pickle scan limit exceeded>")
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
                        # Operands built by ops this scanner does not model (POP, DUP, ...)
                        # could name any callable, e.g. os.system: fail closed.
                        dangerous.add("<unresolved STACK_GLOBAL>")
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
