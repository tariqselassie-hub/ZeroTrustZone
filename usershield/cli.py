"""
Unified Command-Line Interface for UserShield.
Commands:
  - run: Execute local model runtime (llama.cpp) with pre-flight cryptographic gate
  - sign: Cryptographically sign a model weight or context file (detached .sig)
  - verify: Verify integrity of a model weight or context file offline
  - keygen: Generate Ed25519 or RSA-PSS keypair
  - fingerprint: Display anonymous, deterministic local hardware hash
  - license: Inspect or test air-gapped machine license
"""

import sys
import os
import argparse
from typing import List

try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from usershield.core.crypto import UserShieldSigner, UserShieldVerifier, generate_keypair
from usershield.core.trust_store import TrustStore
from usershield.core.validator import PreFlightValidator
from usershield.lic.fingerprint import HardwareFingerprint
from usershield.lic.manager import LicenseManager
from usershield.runners.llama_cpp import run_llama_protected
from usershield.ui.banners import (
    print_header,
    print_audit_table,
    print_lockdown_banner,
    print_summary_card,
)

def cmd_run(args: argparse.Namespace, passthrough: List[str]) -> int:
    trust_store = TrustStore([args.trust_store] if args.trust_store else None)
    
    # Check if Pro license is active
    lic_mgr = LicenseManager(custom_lic_path=args.license)
    is_licensed, lic_status, _ = lic_mgr.verify_license()
    operating_mode = "PRO ($0.99 Machine-Bound)" if is_licensed else "COMMUNITY (FOSS)"

    return run_llama_protected(
        llama_bin=args.llama_bin,
        passthrough_args=passthrough,
        trust_store=trust_store,
        operating_mode=operating_mode,
    )

def cmd_sign(args: argparse.Namespace) -> int:
    try:
        signer = UserShieldSigner(args.key)
        out_sig = signer.sign_file(args.target, output_sig_path=args.out)
        print(f"[SUCCESS] Detached signature generated: {out_sig}")
        return 0
    except Exception as e:
        print(f"[ERROR] Signing failed: {e}", file=sys.stderr)
        return 1

def cmd_verify(args: argparse.Namespace) -> int:
    trust_store = TrustStore([args.trust_store] if args.trust_store else None)
    validator = PreFlightValidator(trust_store)
    
    row = validator.validate_file(args.target, sig_path=args.sig)
    print_audit_table([row])

    if row["status"] == "VERIFIED":
        print(f"[PASS] File attested by authority: {row['key']} ({row['algo']})")
        return 0
    else:
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
    print_header(title="USERSHIELD — HARDWARE FINGERPRINT", subtitle="Anonymous Local Identity Generator")
    raw = HardwareFingerprint.get_raw_components()
    fp = HardwareFingerprint.compute_fingerprint()
    print(f"Raw Components  : {raw}")
    print(f"Machine Hash    : {fp}")
    print("\nNote: This anonymous hash is bound 1-to-1 to this hardware for the $0.99 Pro license.")
    print("Zero personal data or telemetry is transmitted.\n")
    return 0

def cmd_license(args: argparse.Namespace) -> int:
    print_header(title="USERSHIELD — LICENSE SENTINEL", subtitle="Air-Gapped Offline Token Verifier")
    lic_mgr = LicenseManager(custom_lic_path=args.license)
    is_valid, msg, meta = lic_mgr.verify_license()
    print(f"Status           : {'VALID' if is_valid else 'UNLICENSED'}")
    print(f"Message          : {msg}")
    if meta:
        for k, v in meta.items():
            if k != "signature":
                print(f"  {k:<15}: {v}")
    return 0 if is_valid else 1

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usershield",
        description="UserShield: Offline-First Zero-Trust Cryptographic Firewall for Local AI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Run subparser
    run_p = subparsers.add_parser("run", help="Run llama-cli / llama.cpp with pre-flight protection")
    run_p.add_argument("--llama-bin", default="./llama-cli", help="Path to llama-cli / llama.cpp binary")
    run_p.add_argument("--trust-store", default="./keys", help="Directory containing trusted public keys")
    run_p.add_argument("--license", default=None, help="Path to custom usershield.lic file")

    # Sign subparser
    sign_p = subparsers.add_parser("sign", help="Sign a model weight or context payload")
    sign_p.add_argument("target", help="File to sign (e.g. model.gguf, context.txt)")
    sign_p.add_argument("--key", required=True, help="Path to private signing key (.pem)")
    sign_p.add_argument("--out", default=None, help="Output signature path (defaults to <target>.sig)")

    # Verify subparser
    ver_p = subparsers.add_parser("verify", help="Verify integrity of an asset against trust store")
    ver_p.add_argument("target", help="File to verify")
    ver_p.add_argument("--sig", default=None, help="Detached .sig path (defaults to <target>.sig)")
    ver_p.add_argument("--trust-store", default="./keys", help="Directory containing trusted public keys")

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
    lic_p.add_argument("--license", default=None, help="Path to usershield.lic file")

    return parser

def main():
    parser = build_parser()
    
    # Check if 'run' command is invoked to properly pass through trailing args to llama.cpp
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        # Separate known flags for run vs passthrough flags
        args, passthrough = parser.parse_known_args()
        sys.exit(cmd_run(args, passthrough))
    else:
        args = parser.parse_args()
        if not args.command:
            parser.print_help()
            sys.exit(0)
            
        handlers = {
            "sign": cmd_sign,
            "verify": cmd_verify,
            "keygen": cmd_keygen,
            "fingerprint": cmd_fingerprint,
            "license": cmd_license,
        }
        handler = handlers.get(args.command)
        if handler:
            sys.exit(handler(args))
        else:
            parser.print_help()
            sys.exit(1)

def run_cli():
    """Entrypoint for `usershield-run` script."""
    sys.argv.insert(1, "run")
    main()

def sign_cli():
    """Entrypoint for `usershield-sign` script."""
    sys.argv.insert(1, "sign")
    main()

def verify_cli():
    """Entrypoint for `usershield-verify` script."""
    sys.argv.insert(1, "verify")
    main()

def license_cli():
    """Entrypoint for `usershield-lic` script."""
    sys.argv.insert(1, "license")
    main()

if __name__ == "__main__":
    main()
