"""
llama.cpp / llama-cli Pre-Flight Execution Runner for ZTZ.
Intercepts command line arguments, validates model weights and context payloads offline,
and halts execution before process memory allocation if invariants are violated.
"""

import os
import re
import sys
import shutil
import subprocess
import tempfile
from typing import Dict, Iterator, List, Optional, Tuple
from ztz.core.trust_store import TrustStore
from ztz.core.validator import PreFlightValidator
from ztz.core.file_pin import FD_BINDING, changed_files, load_paths, pass_fds, pin_files, unpin_files
from ztz.ui.banners import (
    print_header,
    print_phase,
    print_audit_table,
    print_lockdown_banner,
    print_summary_card,
)

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

def _iter_file_args(args: List[str]) -> Iterator[Tuple[int, str, str, bool]]:
    """
    Yields (index, flag, path, inline) for every file argument; inline means
    args[index] is '--flag=path', otherwise args[index] is the path itself.
    Raises ValueError on argument injection or on remote-fetch flags (see REMOTE_FLAGS).
    """
    i = 0
    while i < len(args):
        flag, value = _split_flag(args[i])
        if flag in REMOTE_FLAGS:
            raise ValueError(
                f"Remote model fetch '{flag}' is forbidden: weights must be local and attested"
            )
        if flag in FILE_FLAGS:
            inline = value is not None
            if not inline:
                if i + 1 >= len(args):
                    raise ValueError(f"Flag '{flag}' is missing its file path")
                value = args[i + 1]
                i += 1
            if value.startswith("-"):
                raise ValueError(f"Argument Injection Detected: Expected file path, got flag '{value}'")
            yield i, flag, value, inline
        i += 1

def extract_target_files(args: List[str]) -> List[str]:
    """
    Extracts every file llama.cpp would load from its CLI arguments (see FILE_FLAGS).
    Raises ValueError on argument injection or on remote-fetch flags (see REMOTE_FLAGS).
    """
    return [path for _, _, path, _ in _iter_file_args(args)]

def bind_target_files(args: List[str], mapping: Dict[str, str]) -> List[str]:
    """Returns a copy of args with every file argument replaced by mapping[path]."""
    bound = list(args)
    for i, flag, path, inline in _iter_file_args(args):
        new = mapping.get(path, path)
        bound[i] = f"{flag}={new}" if inline else new
    return bound

# llama.cpp only loads sibling shards when the given path is the first split,
# named exactly <prefix>-00001-of-NNNNN.gguf (llama_split_prefix), and then opens
# <prefix>-0000i-of-NNNNN.gguf by name.
_SPLIT_HEAD = re.compile(r"^(?P<prefix>.+)-00001-of-(?P<count>\d{5})\.gguf$")

def split_shards(path: str) -> List[str]:
    """All shards llama.cpp would load for path (just [path] if it is not a split head)."""
    m = _SPLIT_HEAD.match(path)
    if not m or int(m["count"]) < 2:
        return [path]
    count = int(m["count"])
    return [f"{m['prefix']}-{i:05d}-of-{count:05d}.gguf" for i in range(1, count + 1)]

def expand_split_targets(targets: List[str]) -> List[str]:
    """targets plus every sibling shard of split GGUF heads, in order, without duplicates."""
    return list(dict.fromkeys(s for t in targets for s in split_shards(t)))

def _link_split_shards(targets: List[str], bound: Dict[str, str]) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Linux: the runtime gets /proc/self/fd/N paths, which carry no shard name, so
    llama.cpp could not find a split model's siblings. For each split head, build a
    private directory of symlinks named like the shards, each pointing at its
    pinned descriptor, and point the head's argument at it (updates bound in place).
    Returns (directory to remove after the run or None, {symlink: descriptor path}).

    Residual risk: a process running as the same user can still replace these
    symlinks between the pre-launch check and llama.cpp opening the shards.
    """
    heads = [t for t in dict.fromkeys(targets) if len(split_shards(t)) > 1]
    if not FD_BINDING or not heads:
        return None, {}
    root = tempfile.mkdtemp(prefix="ztz-split-")  # 0700
    links = {}
    for n, head in enumerate(heads):
        group = os.path.join(root, str(n))
        os.mkdir(group, 0o700)
        for shard in split_shards(head):
            link = os.path.join(group, os.path.basename(shard))
            os.symlink(bound[shard], link)
            links[link] = bound[shard]
        bound[head] = os.path.join(group, os.path.basename(head))
    return root, links

def _split_links_intact(links: Dict[str, str]) -> bool:
    """True if every shard symlink still points at its own pinned descriptor."""
    try:
        return all(os.readlink(link) == target for link, target in links.items())
    except OSError:
        return False

def run_llama_protected(
    llama_bin: str,
    safe_args: List[str],
    trust_store: TrustStore,
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

    # Sibling shards of a split GGUF are loaded too, so they are attested and pinned too.
    files = expand_split_targets(targets)

    # TOCTOU Protection: pin files before validation, hold until the runtime exits
    try:
        pins = pin_files(files)
    except OSError as e:
        print_lockdown_banner(
            failed_target=e.filename or "<unknown>",
            reason=f"LOCK_FAILED: cannot pin file against modification ({e.strerror}). "
                   "Another process may have it open for writing.",
        )
        return 1
    split_dir = None
    try:
        bound = load_paths(pins)
        with PreFlightValidator(trust_store, use_cache=use_cache) as validator:
            all_clean, rows, elapsed = validator.audit_batch(files, read_paths=bound)

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
            )
            # Abort before memory allocation
            return 1

        print_summary_card(
            status="PASS (INVARIANTS CONFIRMED)",
            total_checked=len(rows),
            passed=passed_count,
            failed=failed_count,
            duration_sec=elapsed,
        )

        split_dir, split_links = _link_split_shards(targets, bound)

        changed = changed_files(pins)
        if changed or not _split_links_intact(split_links):
            print_lockdown_banner(
                failed_target=changed[0] if changed else split_dir,
                reason="MODIFIED_AFTER_PIN: file changed or was replaced during verification",
            )
            return 1

        print_phase(2, f"Passing Execution to Runtime Binary: {os.path.basename(safe_bin)}")
        # Linux: the runtime opens the verified descriptors (/proc/self/fd/N), not the paths;
        # split heads point into split_dir, whose shard-named symlinks lead to the descriptors.
        cmd = [safe_bin] + bind_target_files(safe_args, bound)

        proc = subprocess.Popen(cmd, shell=False, close_fds=True, pass_fds=pass_fds(pins))
        proc.wait()
        return proc.returncode
    except FileNotFoundError:
        print(f"\n[ZTZ ERROR] Target inference binary not found: {llama_bin}", file=sys.stderr)
        return 127
    finally:
        if split_dir:
            shutil.rmtree(split_dir, ignore_errors=True)
        unpin_files(pins)
