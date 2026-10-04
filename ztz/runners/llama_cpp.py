"""
llama.cpp / llama-cli Pre-Flight Execution Runner for ZTZ.
Intercepts command line arguments, validates model weights and context payloads offline,
and halts execution before process memory allocation if invariants are violated.
"""

import os
import sys
import shutil
import subprocess
from typing import List, Any
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator
from ztz.ui.banners import (
    print_header,
    print_phase,
    print_audit_table,
    print_lockdown_banner,
    print_summary_card,
)

def _acquire_locks(targets: List[str]) -> List[Any]:
    locks = []
    if os.name != 'nt':
        import fcntl
        for t in targets:
            if os.path.exists(t):
                fd = None
                try:
                    # CWE-775: Open without O_CLOEXEC to hold lock in parent.
                    # close_fds=True in Popen ensures the child does not inherit it.
                    fd = os.open(t, os.O_RDONLY)  # karnak: ignore
                    fcntl.flock(fd, fcntl.LOCK_SH)
                    locks.append(fd)
                except Exception:
                    if fd is not None:
                        os.close(fd)
    return locks

def _release_locks(locks: List[Any]):
    if os.name != 'nt':
        try:
            import fcntl
            for fd in locks:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        except Exception:
            pass

# Flags whose value is a file llama.cpp loads into memory (weights, adapters, context).
# Every one of these must be attested, or it becomes an unverified side-loading channel.
FILE_FLAGS = frozenset({
    # Weights & adapters
    "-m", "--model",
    "-md", "--model-draft",
    "-mv", "--model-vocoder",
    "-mm", "--mmproj",
    "--lora", "--lora-scaled",
    "--control-vector", "--control-vector-scaled",
    # Context payloads
    "-f", "--file", "--prompt-file",
    "-bf", "--binary-file",
    "-sysf", "--system-prompt-file",
    "--grammar-file",
    "-jf", "--json-schema-file",
    "--chat-template-file",
})

# Flags that make llama.cpp fetch weights from the network, bypassing local attestation.
REMOTE_FLAGS = frozenset({
    "-mu", "--model-url",
    "-hf", "-hfr", "--hf-repo",
    "-hff", "--hf-file",
    "-hfd", "-hfrd", "--hf-repo-draft",
    "-hfv", "-hfrv", "--hf-repo-v",
    "-hffv", "--hf-file-v",
    "-dr", "--docker-repo",
    "--mmproj-url",
})

def _split_flag(arg: str):
    if arg.startswith("--") and "=" in arg:
        flag, value = arg.split("=", 1)
        return flag, value
    return arg, None

def extract_target_files(args: List[str]) -> List[str]:
    """
    Extracts every file llama.cpp would load from its CLI arguments (see FILE_FLAGS).
    Raises ValueError on argument injection or on remote-fetch flags (see REMOTE_FLAGS).
    """
    targets = []
    i = 0
    while i < len(args):
        flag, value = _split_flag(args[i])
        if flag in REMOTE_FLAGS:
            raise ValueError(
                f"Remote model fetch '{flag}' is forbidden: weights must be local and attested"
            )
        if flag in FILE_FLAGS:
            if value is None:
                if i + 1 >= len(args):
                    raise ValueError(f"Flag '{flag}' is missing its file path")
                value = args[i + 1]
                i += 1
            if value.startswith("-"):
                raise ValueError(f"Argument Injection Detected: Expected file path, got flag '{value}'")
            targets.append(value)
        i += 1
    return targets

def run_llama_protected(
    llama_bin: str,
    safe_args: List[str],
    trust_store: TrustStore,
    operating_mode: str = "COMMUNITY",
    use_cache: bool = True,
) -> int:
    """
    Executes llama.cpp within the ZTZ pre-flight quarantine boundary.
    """
    print_header()
    print_phase(1, "Cryptographic Invariant & Attestation Audit")

    # Mitigate CWE-78 by resolving and validating the executable via shutil.which
    safe_bin = shutil.which(llama_bin)
    if not safe_bin:
        print(f"[ZTZ ERROR] Binary not found or not executable: {llama_bin}", file=sys.stderr)
        return 127

    try:
        targets = extract_target_files(safe_args)
    except ValueError as e:
        print_lockdown_banner(failed_target="<command line>", reason=str(e))
        return 1

    if not targets:
        print("[ZTZ] No model (-m) or file (-f) arguments found in command.")
        print("[ZTZ] Direct execution allowed for non-file commands.\n")
        cmd = [safe_bin] + safe_args
        # Explicit shell=False to satisfy taint algebra projection
        return subprocess.run(cmd, check=False, shell=False, close_fds=True).returncode  # karnak: ignore

    # TOCTOU Protection: Acquire shared locks before validation
    locks = _acquire_locks(targets)
    try:
        validator = PreFlightValidator(trust_store, use_cache=use_cache)
        all_clean, rows, elapsed = validator.audit_batch(targets)

        # Print the structured Unicode audit table
        print_audit_table(rows)

        passed_count = sum(1 for r in rows if r["status"] in ("VERIFIED", "VERIFIED_CACHE"))
        failed_count = len(rows) - passed_count

        if not all_clean:
            failed_item = next(r for r in rows if r["status"] not in ("VERIFIED", "VERIFIED_CACHE"))
            print_lockdown_banner(
                failed_target=failed_item["full_path"],
                reason=f"{failed_item['status']}: {failed_item.get('error')}",
            )
            print_summary_card(
                status="CRITICAL LOCKDOWN (ABORTED)",
                total_checked=len(rows),
                passed=passed_count,
                failed=failed_count,
                duration_sec=elapsed,
                mode=operating_mode,
            )
            # Abort before memory allocation
            return 1

        print_summary_card(
            status="PASS (INVARIANTS CONFIRMED)",
            total_checked=len(rows),
            passed=passed_count,
            failed=failed_count,
            duration_sec=elapsed,
            mode=operating_mode,
        )

        print_phase(2, f"Passing Execution to Runtime Binary: {os.path.basename(safe_bin)}")
        cmd = [safe_bin] + safe_args
        
        proc = subprocess.Popen(cmd, shell=False, close_fds=True)
        proc.wait()
        return proc.returncode
    except FileNotFoundError:
        print(f"\n[ZTZ ERROR] Target inference binary not found: {llama_bin}", file=sys.stderr)
        return 127
    finally:
        # Release locks after the subprocess has safely launched and acquired its own handles
        _release_locks(locks)
