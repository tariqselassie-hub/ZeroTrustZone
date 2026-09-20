"""
llama.cpp / llama-cli Pre-Flight Execution Runner for UserShield.
Intercepts command line arguments, validates model weights and context payloads offline,
and halts execution before process memory allocation if invariants are violated.
"""

import os
import sys
import subprocess
from typing import List
from usershield.core.trust_store import TrustStore
from usershield.core.validator import PreFlightValidator
from usershield.ui.banners import (
    print_header,
    print_phase,
    print_audit_table,
    print_lockdown_banner,
    print_summary_card,
)

def extract_target_files(args: List[str]) -> List[str]:
    """
    Extracts candidate model and context files from llama.cpp CLI arguments.
    Inspects flags like -m, --model, -f, --file, --prompt-file.
    """
    targets = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-m", "--model", "-f", "--file", "--prompt-file"):
            if i + 1 < len(args):
                targets.append(args[i + 1])
                i += 2
                continue
        elif arg.startswith(("--model=", "--file=", "--prompt-file=")):
            targets.append(arg.split("=", 1)[1])
        i += 1
    return targets

def run_llama_protected(
    llama_bin: str,
    passthrough_args: List[str],
    trust_store: TrustStore,
    operating_mode: str = "COMMUNITY",
    use_cache: bool = True,
) -> int:
    """
    Executes llama.cpp within the UserShield pre-flight quarantine boundary.
    """
    print_header()
    print_phase(1, "Cryptographic Invariant & Attestation Audit")

    targets = extract_target_files(passthrough_args)
    if not targets:
        print("[USERSHIELD] No model (-m) or file (-f) arguments found in command.")
        print("[USERSHIELD] Direct execution allowed for non-file commands.\n")
        cmd = [llama_bin] + passthrough_args
        return subprocess.run(cmd).returncode

    validator = PreFlightValidator(trust_store, use_cache=use_cache)
    all_clean, rows, elapsed = validator.audit_batch(targets)

    # Print the Deen structured Unicode audit table
    print_audit_table(rows)

    passed_count = sum(1 for r in rows if r["status"] == "VERIFIED")
    failed_count = len(rows) - passed_count

    if not all_clean:
        failed_item = next(r for r in rows if r["status"] != "VERIFIED")
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

    print_phase(2, f"Passing Execution to Runtime Binary: {os.path.basename(llama_bin)}")
    cmd = [llama_bin] + passthrough_args
    try:
        proc = subprocess.run(cmd)
        return proc.returncode
    except FileNotFoundError:
        print(f"\n[USERSHIELD ERROR] Target inference binary not found: {llama_bin}", file=sys.stderr)
        return 127
