"""
Unified Command-Line Interface for ZeroTrustZone (ZTZ).
Commands:
  - init: Initialize global configuration, trust store, and Root Authority keypair
  - doctor: Comprehensive system health, crypto, and runtime diagnostics
  - models: Discover, inspect, and attest local Ollama and GGUF models
  - run: Execute local model runtime (llama.cpp) with pre-flight cryptographic gate
  - proxy: Start the Ollama/LM Studio reverse proxy interceptor
  - sign: Cryptographically sign a model weight or context file (detached .sig)
  - verify: Verify integrity of a model weight or context file offline
  - inspect-model: Inspect GGUF / Safetensors / PyTorch weights for bytecode risks
  - context-scan: Scan prompt or context file for leaked secrets & tokens
  - keygen: Generate Ed25519 or RSA-PSS keypair
  - fingerprint: Display anonymous, deterministic local hardware hash
  - license: Inspect or test air-gapped machine license
  - cache: Manage the instant attestation cache
"""

import sys
import os
import json
import argparse
from typing import List

try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from ztz.core.crypto import ZTZSigner, ZTZVerifier, generate_keypair
from ztz.core.trust_store import TrustStore, find_private_key
from ztz.core.validator import PreFlightValidator
from ztz.core.setup import init_environment
from ztz.core.doctor import run_diagnostics
from ztz.core.model_manager import (
    discover_ollama_models,
    sign_model_target,
    resolve_model_target,
)
from ztz.lic.fingerprint import HardwareFingerprint
from ztz.lic.manager import LicenseManager
from ztz.runners.llama_cpp import run_llama_protected
from ztz.runners.proxy import run_proxy
from ztz.ui.banners import (
    print_header,
    print_audit_table,
    print_lockdown_banner,
    print_summary_card,
    print_init_card,
    print_doctor_report,
    print_model_inventory_table,
)

def cmd_init(args: argparse.Namespace) -> int:
    try:
        info = init_environment(force=args.force, key_type=args.type)
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2))
        else:
            print_init_card(info)
        return 0
    except Exception as e:
        print(f"[ERROR] Initialization failed: {e}", file=sys.stderr)
        return 1

def cmd_doctor(args: argparse.Namespace) -> int:
    try:
        checks = run_diagnostics()
        if getattr(args, "json", False):
            print(json.dumps(checks, indent=2))
        else:
            print_doctor_report(checks)
        return 0
    except Exception as e:
        print(f"[ERROR] Diagnostics check failed: {e}", file=sys.stderr)
        return 1

def cmd_models(args: argparse.Namespace) -> int:
    action = getattr(args, "models_action", None)
    if action in ("list", "scan", None):
        models = discover_ollama_models(args.dir)
        if getattr(args, "json", False):
            print(json.dumps(models, indent=2))
        else:
            print_header(title="ZEROTRUSTZONE — LOCAL MODEL INVENTORY", subtitle="Ollama & Local Runtime Attestation Sentinel")
            if not models:
                print("No Ollama models detected. Use Ollama to pull models or verify your storage directory.")
            else:
                print_model_inventory_table(models)
                verified = sum(1 for m in models if m.get("status") in ("VERIFIED", "VERIFIED_CACHE"))
                unsigned = len(models) - verified
                print(f"\nInventory: {len(models)} total | {verified} verified | {unsigned} unsigned")
                if unsigned > 0:
                    print("Tip: Run 'ztz models sign <model_name>' to sign and attest any model.")
        return 0
    elif action == "sign":
        try:
            res = sign_model_target(args.target, private_key_path=args.key, model_base_dir=args.dir)
            if getattr(args, "json", False):
                print(json.dumps(res, indent=2))
            else:
                print(f"[SUCCESS] Model '{res['name']}' signed successfully.")
                print(f"  Physical File : {res['blob_path']}")
                print(f"  Signature     : {res['sig_path']}")
                print(f"  Signer Key    : {res['signer_key']}")
            return 0
        except Exception as e:
            print(f"[ERROR] Model signing failed: {e}", file=sys.stderr)
            return 1
    elif action == "inspect":
        from ztz.core.model_inspector import ModelFormatInspector
        target_info = resolve_model_target(args.target, args.dir)
        if not target_info or not os.path.exists(target_info["blob_path"]):
            print(f"[ERROR] Model not found: {args.target}", file=sys.stderr)
            return 1
        rep = ModelFormatInspector.inspect(target_info["blob_path"])
        if getattr(args, "json", False):
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print_header(title="ZEROTRUSTZONE — MODEL WEIGHT INSPECTOR", subtitle="Container & Bytecode Security Probe")
            print(f"Target Model    : {args.target}")
            print(f"Physical File   : {rep.file_path}")
            print(f"Format          : {rep.format}")
            print(f"Size            : {rep.file_size_bytes} bytes")
            print(f"Safety Verdict  : {'SAFE CONTAINER' if rep.is_safe_format else 'RISKY CONTAINER'}")
            print(f"Risk Level      : {rep.risk_level}")
            if rep.metadata:
                print("Metadata        :")
                for k, v in rep.metadata.items():
                    print(f"  - {k:<20}: {v}")
            if rep.warnings:
                print("Warnings        :")
                for w in rep.warnings:
                    print(f"  ⚠ {w}")
        return 0 if rep.is_safe_format else 1
    else:
        print("[ERROR] Unknown action. Use 'list', 'sign', or 'inspect'.", file=sys.stderr)
        return 1

def cmd_run(args: argparse.Namespace, passthrough: List[str]) -> int:
    trust_store = TrustStore([args.trust_store] if args.trust_store else None)
    
    lic_mgr = LicenseManager(custom_lic_path=args.license)
    is_licensed, lic_status, _ = lic_mgr.verify_license()
    operating_mode = "PRO ($0.99 Machine-Bound)" if is_licensed else "COMMUNITY (FOSS)"

    return run_llama_protected(
        llama_bin=args.llama_bin,
        safe_args=passthrough,
        trust_store=trust_store,
        operating_mode=operating_mode,
        use_cache=not args.no_cache,
    )

def cmd_proxy(args: argparse.Namespace) -> int:
    try:
        run_proxy(
            host=args.host,
            port=args.port,
            upstream_port=args.upstream_port,
            trust_store_path=args.trust_store,
            use_cache=not args.no_cache,
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"[ERROR] Proxy failed: {e}", file=sys.stderr)
        return 1

def cmd_sign(args: argparse.Namespace) -> int:
    try:
        key_path = find_private_key(args.key)
        if not key_path:
            print("[ERROR] No private key found. Run 'ztz init' or provide --key <path>.", file=sys.stderr)
            return 1
        signer = ZTZSigner(key_path)
        out_sig = signer.sign_file(args.target, output_sig_path=args.out)
        print(f"[SUCCESS] Detached signature generated: {out_sig}")
        return 0
    except Exception as e:
        print(f"[ERROR] Signing failed: {e}", file=sys.stderr)
        return 1

def cmd_verify(args: argparse.Namespace) -> int:
    trust_store = TrustStore([args.trust_store] if args.trust_store else None)
    validator = PreFlightValidator(trust_store, use_cache=not args.no_cache)
    
    row = validator.validate_file(args.target, sig_path=args.sig)
    if getattr(args, "json", False):
        print(json.dumps(row, indent=2))
    else:
        print_audit_table([row])

    if row["status"] in ("VERIFIED", "VERIFIED_CACHE"):
        cache_note = " [from instant cache]" if row["status"] == "VERIFIED_CACHE" else ""
        if not getattr(args, "json", False):
            print(f"[PASS] File attested by authority: {row['key']} ({row['algo']}){cache_note}")
        return 0
    else:
        if not getattr(args, "json", False):
            print_lockdown_banner(args.target, reason=f"{row['status']}: {row['error']}")
        return 1

def cmd_keygen(args: argparse.Namespace) -> int:
    try:
        priv, pub = generate_keypair(
            key_type=args.type,
            out_dir=args.out_dir,
            name=args.name,
            rsa_bits=args.bits,
        )
        print(f"[SUCCESS] Keypair generated:")
        print(f"  Private key (KEEP SECRET): {priv}")
        print(f"  Public key  (DISTRIBUTE) : {pub}")
        return 0
    except Exception as e:
        print(f"[ERROR] Key generation failed: {e}", file=sys.stderr)
        return 1

def cmd_fingerprint(args: argparse.Namespace) -> int:
    print_header(title="ZTZ — HARDWARE FINGERPRINT", subtitle="Anonymous Local Identity Generator")
    raw = HardwareFingerprint.get_raw_components()
    fp = HardwareFingerprint.compute_fingerprint()
    print(f"Raw Components  : {raw}")
    print(f"Machine Hash    : {fp}")
    print("\nNote: This anonymous hash is bound 1-to-1 to this hardware for the $0.99 Pro license.")
    print("Zero personal data or telemetry is transmitted.\n")
    return 0

def cmd_license(args: argparse.Namespace) -> int:
    print_header(title="ZTZ — LICENSE SENTINEL", subtitle="Air-Gapped Offline Token Verifier")
    lic_mgr = LicenseManager(custom_lic_path=args.license)
    is_valid, msg, meta = lic_mgr.verify_license()
    print(f"Status           : {'VALID' if is_valid else 'UNLICENSED'}")
    print(f"Message          : {msg}")
    if meta:
        for k, v in meta.items():
            if k != "signature":
                print(f"  {k:<15}: {v}")
    return 0 if is_valid else 1

def cmd_cache(args: argparse.Namespace) -> int:
    if args.action == "clear":
        from ztz.core.cache import AttestationCache
        cache = AttestationCache()
        cache.clear()
        print("[SUCCESS] Instant Attestation Cache cleared.")
        return 0
    return 1

def cmd_service(args: argparse.Namespace) -> int:
    print(
        f"[ERROR] 'ztz service {args.action}' is not implemented yet. "
        "Run 'ztz proxy' under your platform's service manager instead.",
        file=sys.stderr,
    )
    return 2

def cmd_inspect_model(args: argparse.Namespace) -> int:
    from ztz.core.model_inspector import ModelFormatInspector
    rep = ModelFormatInspector.inspect(args.target)
    if getattr(args, "json", False):
        print(json.dumps(rep.to_dict(), indent=2))
        return 0 if rep.is_safe_format else 1

    print_header(title="ZEROTRUSTZONE — MODEL WEIGHT INSPECTOR", subtitle="Container & Bytecode Security Probe")
    print(f"Target File     : {rep.file_path}")
    print(f"Format          : {rep.format}")
    print(f"Size            : {rep.file_size_bytes} bytes")
    print(f"Safety Verdict  : {'SAFE CONTAINER' if rep.is_safe_format else 'RISKY CONTAINER'}")
    print(f"Risk Level      : {rep.risk_level}")
    if rep.metadata:
        print("Metadata        :")
        for k, v in rep.metadata.items():
            print(f"  - {k:<20}: {v}")
    if rep.warnings:
        print("Warnings        :")
        for w in rep.warnings:
            print(f"  ⚠ {w}")
    return 0 if rep.is_safe_format else 1

def cmd_context_scan(args: argparse.Namespace) -> int:
    from ztz.core.context_shield import ContextShield
    
    if args.target == "-":
        content = sys.stdin.read()
    elif os.path.exists(args.target):
        with open(args.target, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    else:
        content = args.target

    res = ContextShield.sanitize(content)
    if getattr(args, "json", False):
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print_header(title="ZEROTRUSTZONE — CONTEXT FIREWALL SCAN", subtitle="Secret Scrubbing & Pre-Flight Token Sanitizer")
        print(f"Total Redactions : {res.redactions_count}")
        print(f"Payload Digest   : {res.digest_sha256}")
        if res.findings:
            print("Detected Secrets :")
            for f in res.findings:
                cat = f.get('category') or f.get('type') or 'SECRET'
                offset = f.get('offset', 0)
                length = f.get('length', 0)
                print(f"  🚨 [{cat}] Offset: {offset} (length: {length})")
        else:
            print("✔ No sensitive secrets or private keys detected in context payload.")
    
    if args.out and res.clean_text:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(res.clean_text)
        if not getattr(args, "json", False):
            print(f"[SUCCESS] Sanitized content written to: {args.out}")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ztz",
        description=(
            "🛡️ ZeroTrustZone (ZTZ): Zero-Trust Cryptographic Pre-Flight Firewall\n\n"
            "Secures local AI inference by enforcing strict asymmetric cryptographic\n"
            "attestation on model weights and contexts before memory allocation."
        ),
        epilog="Run 'ztz <command> --help' for detailed usage instructions.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Init subparser
    init_p = subparsers.add_parser("init", help="Initialize ZeroTrustZone (ZTZ) configuration, global trust store, and keypair")
    init_p.add_argument("--force", action="store_true", help="Force re-generation of keys and config")
    init_p.add_argument("--type", choices=["ed25519", "rsa"], default="ed25519", help="Key algorithm (default: ed25519)")
    init_p.add_argument("--json", action="store_true", help="Output initialization status in JSON format")

    # Doctor subparser
    doctor_p = subparsers.add_parser("doctor", help="Run comprehensive system health, runtime, and security diagnostics")
    doctor_p.add_argument("--json", action="store_true", help="Output diagnostic report in JSON format")

    # Models subparser
    models_p = subparsers.add_parser("models", help="Discover, inspect, and attest local Ollama and GGUF models")
    models_sub = models_p.add_subparsers(dest="models_action", help="Models action (list, sign, inspect)")
    
    models_list_p = models_sub.add_parser("list", help="List local Ollama models with attestation status")
    models_list_p.add_argument("--dir", default=None, help="Custom Ollama models directory")
    models_list_p.add_argument("--json", action="store_true", help="Output model inventory in JSON format")

    models_sign_p = models_sub.add_parser("sign", help="Sign a model by tag name or path")
    models_sign_p.add_argument("target", help="Model name (e.g. llama3:latest) or physical file path")
    models_sign_p.add_argument("--key", default=None, help="Path to private signing key (.pem)")
    models_sign_p.add_argument("--dir", default=None, help="Custom Ollama models directory")
    models_sign_p.add_argument("--json", action="store_true", help="Output sign status in JSON format")

    models_insp_p = models_sub.add_parser("inspect", help="Inspect a model container by tag name or path")
    models_insp_p.add_argument("target", help="Model name (e.g. llama3:latest) or physical file path")
    models_insp_p.add_argument("--dir", default=None, help="Custom Ollama models directory")
    models_insp_p.add_argument("--json", action="store_true", help="Output report in JSON format")

    # Run subparser
    run_p = subparsers.add_parser("run", help="Run llama-cli / llama.cpp with pre-flight protection")
    _add_run_options(run_p)

    # Proxy subparser
    proxy_p = subparsers.add_parser("proxy", help="Start the Ollama/LM Studio reverse proxy interceptor")
    proxy_p.add_argument("--host", default="127.0.0.1", help="Host to bind proxy")
    proxy_p.add_argument("--port", type=int, default=11434, help="Port to listen on (default 11434)")
    proxy_p.add_argument("--upstream-port", type=int, default=11435, help="Port of the real backend")
    proxy_p.add_argument("--trust-store", default=None, help="Directory containing trusted public keys")
    proxy_p.add_argument("--no-cache", action="store_true", help="Bypass the instant attestation cache")

    # Sign subparser
    sign_p = subparsers.add_parser("sign", help="Sign a model weight or context payload")
    sign_p.add_argument("target", help="File to sign (e.g. model.gguf, context.txt)")
    sign_p.add_argument("--key", default=None, help="Path to private signing key (.pem, defaults to authority key)")
    sign_p.add_argument("--out", default=None, help="Output signature path (defaults to <target>.sig)")

    # Verify subparser
    ver_p = subparsers.add_parser("verify", help="Verify integrity of an asset against trust store")
    ver_p.add_argument("target", help="File to verify")
    ver_p.add_argument("--sig", default=None, help="Detached .sig path (defaults to <target>.sig)")
    ver_p.add_argument("--trust-store", default=None, help="Directory containing trusted public keys")
    ver_p.add_argument("--no-cache", action="store_true", help="Bypass the instant attestation cache")
    ver_p.add_argument("--json", action="store_true", help="Output verification audit row in JSON format")

    # Keygen subparser
    kg_p = subparsers.add_parser("keygen", help="Generate asymmetric signing keypair")
    kg_p.add_argument("--type", choices=["ed25519", "rsa"], default="ed25519", help="Key algorithm")
    kg_p.add_argument("--out-dir", default="./keys", help="Directory to save keys")
    kg_p.add_argument("--name", default="authority", help="Prefix name for key files")
    kg_p.add_argument("--bits", type=int, default=4096, help="RSA key bits (if type=rsa)")

    # Fingerprint subparser
    subparsers.add_parser("fingerprint", help="Display local anonymous hardware fingerprint")

    # License subparser
    lic_p = subparsers.add_parser("license", help="Verify offline license status")
    lic_p.add_argument("--license", default=None, help="Path to ztz.lic file")

    # Cache subparser
    cache_p = subparsers.add_parser("cache", help="Manage the instant attestation cache")
    cache_p.add_argument("action", choices=["clear"], help="Action to perform (e.g. clear)")

    # Service subparser
    svc_p = subparsers.add_parser("service", help="Manage the ZTZ background daemon (not yet implemented)")
    svc_p.add_argument("action", choices=["install"], help="Action to perform")

    # Inspect-model subparser
    inspect_p = subparsers.add_parser("inspect-model", help="Inspect GGUF / Safetensors / PyTorch weights for structural safety & bytecode risks")
    inspect_p.add_argument("target", help="Model weight file to inspect")
    inspect_p.add_argument("--json", action="store_true", help="Output inspection report in JSON format")

    # Context-scan subparser
    scan_p = subparsers.add_parser("context-scan", help="Scan prompt or context file for leaked API keys, tokens, or private keys")
    scan_p.add_argument("target", help="Text or file path to scan, or '-' for stdin")
    scan_p.add_argument("--out", default=None, help="Optional output path for scrubbed/sanitized text")
    scan_p.add_argument("--json", action="store_true", help="Output findings and audit result in JSON format")

    return parser

def _add_run_options(p: argparse.ArgumentParser):
    p.add_argument("--llama-bin", default="./llama-cli", help="Path to llama-cli / llama.cpp binary")
    p.add_argument("--trust-store", default=None, help="Directory containing trusted public keys")
    p.add_argument("--license", default=None, help="Path to custom ztz.lic file")
    p.add_argument("--no-cache", action="store_true", help="Bypass the instant attestation cache")

def build_run_parser() -> argparse.ArgumentParser:
    """
    Parser for `ztz run` passthrough mode. No -h and no prefix abbreviation, so
    llama.cpp flags such as -hf or --lic... reach the pre-flight guard untouched.
    """
    p = argparse.ArgumentParser(prog="ztz run", add_help=False, allow_abbrev=False)
    _add_run_options(p)
    return p

def main():
    parser = build_parser()

    if len(sys.argv) > 1 and sys.argv[1] == "run":
        args, passthrough = build_run_parser().parse_known_args(sys.argv[2:])
        sys.exit(cmd_run(args, passthrough))
    else:
        args = parser.parse_args()
        if not args.command:
            parser.print_help()
            sys.exit(0)
            
        handlers = {
            "init": cmd_init,
            "doctor": cmd_doctor,
            "models": cmd_models,
            "proxy": cmd_proxy,
            "sign": cmd_sign,
            "verify": cmd_verify,
            "keygen": cmd_keygen,
            "fingerprint": cmd_fingerprint,
            "license": cmd_license,
            "cache": cmd_cache,
            "service": cmd_service,
            "inspect-model": cmd_inspect_model,
            "context-scan": cmd_context_scan,
        }
        handler = handlers.get(args.command)
        if handler:
            sys.exit(handler(args))
        else:
            parser.print_help()
            sys.exit(1)

def run_cli():
    """Entrypoint for `ztz-run` script."""
    sys.argv.insert(1, "run")
    main()

def sign_cli():
    """Entrypoint for `ztz-sign` script."""
    sys.argv.insert(1, "sign")
    main()

def verify_cli():
    """Entrypoint for `ztz-verify` script."""
    sys.argv.insert(1, "verify")
    main()

def license_cli():
    """Entrypoint for `ztz-lic` script."""
    sys.argv.insert(1, "license")
    main()

if __name__ == "__main__":
    main()
