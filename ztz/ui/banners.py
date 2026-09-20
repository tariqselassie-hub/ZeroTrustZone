import sys
import time
from typing import List, Dict, Any, Optional

# Ensure standard output can handle Unicode box-drawing characters on Windows
try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def print_header(title: str = "ZTZ — PRE-FLIGHT GATEWAY", subtitle: str = "Zero-Trust Hardware Attestation Sentinel"):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║{title.center(width)}║")
    print(f"║{subtitle.center(width)}║")
    print(f"╚{'═' * width}╝\n")

def print_phase(phase_num: int, phase_title: str):
    width = 80
    print(f"═" * width)
    print(f" PHASE {phase_num}: {phase_title.upper()}")
    print(f"═" * width)

def print_audit_table(rows: List[Dict[str, Any]]):
    """
    Renders clean single-line Unicode tables:
    ┌──────────────────────┬────────────────────────┬─────────────┬────────────────┐
    │ Target Resource      │ Root of Trust Key      │ Algorithm   │ Status         │
    ├──────────────────────┼────────────────────────┼─────────────┼────────────────┤
    │ ...                  │ ...                    │ ...         │ ...            │
    └──────────────────────┴────────────────────────┴─────────────┴────────────────┘
    """
    col_w = {
        "resource": 30,
        "key": 22,
        "algo": 11,
        "status": 12,
    }
    
    top = f"┌{'─' * col_w['resource']}┬{'─' * col_w['key']}┬{'─' * col_w['algo']}┬{'─' * col_w['status']}┐"
    header = f"│ {'Target Resource':<{col_w['resource']-1}}│ {'Root Authority':<{col_w['key']-1}}│ {'Algorithm':<{col_w['algo']-1}}│ {'Status':<{col_w['status']-1}}│"
    sep = f"├{'─' * col_w['resource']}┼{'─' * col_w['key']}┼{'─' * col_w['algo']}┼{'─' * col_w['status']}┤"
    bottom = f"└{'─' * col_w['resource']}┴{'─' * col_w['key']}┴{'─' * col_w['algo']}┴{'─' * col_w['status']}┘"
    
    print(top)
    print(header)
    print(sep)
    
    for row in rows:
        res = row.get("resource", "")
        if len(res) > col_w["resource"] - 2:
            res = "..." + res[-(col_w["resource"] - 5):]
        key = row.get("key", "None")
        if len(key) > col_w["key"] - 2:
            key = key[:col_w["key"] - 5] + "..."
        algo = row.get("algo", "Unknown")[:col_w["algo"] - 2]
        status = row.get("status", "PENDING")
        
        # Add visual indicator
        if "VERIFIED" in status or "PASS" in status:
            status_display = f"✔ {status}"
        elif "TAMPERED" in status or "FAIL" in status:
            status_display = f"⚡ {status}"
        else:
            status_display = status
            
        print(f"│ {res:<{col_w['resource']-1}}│ {key:<{col_w['key']-1}}│ {algo:<{col_w['algo']-1}}│ {status_display:<{col_w['status']-1}}│")
        
    print(bottom)

def print_lockdown_banner(failed_target: str, reason: str = "Cryptographic invariant violation"):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║ [CRITICAL LOCKDOWN] PAYLOAD ISOLATION TRIGGERED{' ' * (width - 49)}║")
    print(f"╠{'═' * width}╣")
    print(f"║ Target Resource : {failed_target[:width - 21]:<{width - 20}}║")
    print(f"║ Failure Cause   : {reason[:width - 21]:<{width - 20}}║")
    print(f"║ Action Taken    : Process execution aborted before memory allocation.{' ' * (width - 69)}║")
    print(f"║ Security Rule   : Unattested inputs strictly quarantined from hardware.{' ' * (width - 73)}║")
    print(f"╚{'═' * width}╝\n")

def print_summary_card(status: str, total_checked: int, passed: int, failed: int, duration_sec: float, mode: str = "COMMUNITY"):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║                       ZTZ AUDIT SUMMARY                               ║")
    print(f"╠{'═' * width}╣")
    status_str = f"Status           : {status}"
    print(f"║ {status_str:<{width-2}} ║")
    mode_str = f"Operating Mode   : {mode}"
    print(f"║ {mode_str:<{width-2}} ║")
    counts_str = f"Assets Audited   : {total_checked} (Passed: {passed}, Failed: {failed})"
    print(f"║ {counts_str:<{width-2}} ║")
    time_str = f"Duration         : {duration_sec:.4f}s"
    print(f"║ {time_str:<{width-2}} ║")
    print(f"╚{'═' * width}╝\n")
