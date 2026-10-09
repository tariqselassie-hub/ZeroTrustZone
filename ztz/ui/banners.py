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

def print_summary_card(status: str, total_checked: int, passed: int, failed: int, duration_sec: float):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║                       ZTZ AUDIT SUMMARY                               ║")
    print(f"╠{'═' * width}╣")
    status_str = f"Status           : {status}"
    print(f"║ {status_str:<{width-2}} ║")
    counts_str = f"Assets Audited   : {total_checked} (Passed: {passed}, Failed: {failed})"
    print(f"║ {counts_str:<{width-2}} ║")
    time_str = f"Duration         : {duration_sec:.4f}s"
    print(f"║ {time_str:<{width-2}} ║")
    print(f"╚{'═' * width}╝\n")

def print_init_card(info: Dict[str, Any]):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║             ZEROTRUSTZONE (ZTZ) — ENVIRONMENT INITIALIZED             ║")
    print(f"╠{'═' * width}╣")
    print(f"║ Base Home      : {info['home_dir'][:width-20]:<{width-19}}║")
    print(f"║ Trust Store    : {info['keys_dir'][:width-20]:<{width-19}}║")
    print(f"║ Config File    : {info['config_path'][:width-20]:<{width-19}}║")
    print(f"║ Authority Priv : {info['private_key'][:width-20]:<{width-19}}║")
    print(f"║ Authority Pub  : {info['public_key'][:width-20]:<{width-19}}║")
    print(f"╠{'═' * width}╣")
    print(f"║  Next Steps:                                                                 ║")
    print(f"║   1. Run 'ztz doctor' to verify local runtime health                         ║")
    print(f"║   2. Run 'ztz models list' to view local Ollama models                       ║")
    print(f"║   3. Run 'ztz models sign <name>' to sign a model in 1 click                 ║")
    print(f"║   4. Run 'ztz proxy' to guard Ollama / LM Studio inference                   ║")
    print(f"╚{'═' * width}╝\n")

def print_doctor_report(checks: Dict[str, Any]):
    width = 78
    print(f"\n╔{'═' * width}╗")
    print(f"║                ZEROTRUSTZONE — SYSTEM HEALTH & DIAGNOSTICS            ║")
    print(f"╠{'═' * width}╣")
    
    # Platform
    p = checks.get("platform", {})
    p_str = f"OS: {p.get('os')} {p.get('release')} ({p.get('arch')}) | Python {p.get('python_version')}"
    print(f"║ Platform       : {p_str[:width-20]:<{width-19}}║")
    
    # Crypto
    c = checks.get("crypto", {})
    c_icon = "✔" if c.get("ok") else "✖"
    c_str = f"{c_icon} Cryptography {c.get('cryptography_version')} | FP: {c.get('hardware_fingerprint')[:16]}..."
    print(f"║ Crypto Backend : {c_str[:width-20]:<{width-19}}║")
    
    # Trust store
    t = checks.get("trust_store", {})
    t_icon = "✔" if t.get("ok") else "⚠"
    auth_list = ", ".join(t.get("authorities", [])) or "None (Run 'ztz init')"
    t_str = f"{t_icon} {t.get('loaded_authorities_count', 0)} loaded authority key(s): [{auth_list}]"
    print(f"║ Trust Store    : {t_str[:width-20]:<{width-19}}║")
    sign_str = f"{'✔' if t.get('can_sign') else '⚠'} Signing Key: {t.get('default_signing_key') or 'None'}"
    print(f"║ Sign Authority : {sign_str[:width-20]:<{width-19}}║")
    
    # Ollama
    o = checks.get("ollama", {})
    o_status = "ONLINE (Port 11434)" if o.get("service_online") else "OFFLINE"
    o_dir = "Found" if o.get("directory_exists") else "Missing"
    o_str = f"{'✔' if o.get('service_online') else '○'} Service: {o_status} | Storage: {o_dir} ({o.get('models_count', 0)} models, {o.get('signed_models_count', 0)} signed)"
    print(f"║ Ollama Gateway : {o_str[:width-20]:<{width-19}}║")
    
    # Cache
    ca = checks.get("cache", {})
    ca_str = f"{'✔' if ca.get('exists') else '○'} {ca.get('records', 0)} attestation records ({ca.get('size_kb', 0)} KB)"
    print(f"║ SQLite Cache   : {ca_str[:width-20]:<{width-19}}║")
    
    # Context Shield
    cs = checks.get("context_shield", {})
    cs_str = f"✔ {cs.get('active_rules_count', 0)} secret inspection rules armed"
    print(f"║ Context Shield : {cs_str[:width-20]:<{width-19}}║")
    
    # Verdict
    print(f"╠{'═' * width}╣")
    v = checks.get("verdict", "UNKNOWN")
    v_badge = "✔ ALL SYSTEMS SECURE & OPERATIONAL" if v == "READY" else "⚠ ACTION RECOMMENDED: Run 'ztz init'"
    print(f"║ Verdict        : {v_badge:<{width-20}} ║")
    print(f"╚{'═' * width}╝\n")

def print_model_inventory_table(models: List[Dict[str, Any]]):
    col_w = {"tag": 26, "size": 11, "format": 12, "sig": 10, "status": 15}
    top = f"┌{'─' * col_w['tag']}┬{'─' * col_w['size']}┬{'─' * col_w['format']}┬{'─' * col_w['sig']}┬{'─' * col_w['status']}┐"
    header = f"│ {'Model Tag':<{col_w['tag']-1}}│ {'Size':<{col_w['size']-1}}│ {'Container':<{col_w['format']-1}}│ {'Sig':<{col_w['sig']-1}}│ {'Attestation':<{col_w['status']-1}}│"
    sep = f"├{'─' * col_w['tag']}┼{'─' * col_w['size']}┼{'─' * col_w['format']}┼{'─' * col_w['sig']}┼{'─' * col_w['status']}┤"
    bottom = f"└{'─' * col_w['tag']}┴{'─' * col_w['size']}┴{'─' * col_w['format']}┴{'─' * col_w['sig']}┴{'─' * col_w['status']}┘"

    print(top)
    print(header)
    print(sep)

    for m in models:
        tag = m.get("name", "unknown")
        if len(tag) > col_w["tag"] - 2:
            tag = tag[:col_w["tag"] - 5] + "..."
        
        # Human readable size
        bytes_val = m.get("size_bytes", 0)
        if bytes_val > 1024**3:
            size_str = f"{bytes_val / (1024**3):.2f} GB"
        elif bytes_val > 1024**2:
            size_str = f"{bytes_val / (1024**2):.1f} MB"
        else:
            size_str = f"{bytes_val / 1024:.0f} KB"

        fmt = m.get("format", "UNKNOWN")[:col_w["format"]-2]
        has_sig = "YES" if m.get("has_sig") else "NO"
        st = m.get("status", "UNSIGNED")
        if st in ("VERIFIED", "VERIFIED_CACHE"):
            st_display = f"✔ {st[:10]}"
        elif st == "UNSIGNED":
            st_display = "⚠ UNSIGNED"
        else:
            st_display = f"⚡ {st[:10]}"

        print(f"│ {tag:<{col_w['tag']-1}}│ {size_str:<{col_w['size']-1}}│ {fmt:<{col_w['format']-1}}│ {has_sig:<{col_w['sig']-1}}│ {st_display:<{col_w['status']-1}}│")

    print(bottom)

