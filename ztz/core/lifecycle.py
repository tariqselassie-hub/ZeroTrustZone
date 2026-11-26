"""
System lifecycle management for ZeroTrustZone (ZTZ):
  - install_system: initializes ~/.ztz, records install metadata, optionally installs service
  - update_system: checks/applies package & config updates and refreshes the proxy service
  - uninstall_system: stops/removes service and deletes ~/.ztz state (preserving keys unless --purge-keys)
"""

import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

from ztz.core.setup import CONFIG_PATH, ZTZ_HOME, init_environment
from ztz.core.trust_store import DEFAULT_ZTZ_STORE
from ztz.runners import service

Runner = Callable[[Sequence[str]], int]


def get_installed_version() -> str:
    try:
        return importlib.metadata.version("ztz")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


def detect_editable_repo() -> Optional[str]:
    """Returns the repository root if ztz is running from a git checkout, else None."""
    pkg_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if os.path.isdir(os.path.join(pkg_dir, ".git")) and os.path.isfile(os.path.join(pkg_dir, "pyproject.toml")):
        return pkg_dir
    return None


def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    path = config_path or CONFIG_PATH
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_config(config: Dict[str, Any], config_path: Optional[str] = None):
    path = config_path or CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def install_system(
    force: bool = False,
    key_type: str = "ed25519",
    with_service: bool = False,
    service_cfg: Optional[service.ServiceConfig] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Performs full ZTZ system setup:
      1. Initializes ~/.ztz, trust store, keypair, and config.json
      2. Stamps install metadata (version, mode, repo_path, updated_at)
      3. Optionally installs and starts the background proxy service
    """
    repo_path = detect_editable_repo()
    version = get_installed_version()

    if dry_run:
        plan = {
            "action": "install",
            "dry_run": True,
            "version": version,
            "install_mode": "editable" if repo_path else "package",
            "repo_path": repo_path,
            "home_dir": ZTZ_HOME,
            "with_service": with_service,
        }
        if with_service:
            cfg = service_cfg or service.ServiceConfig()
            service.install(cfg, start=True, dry_run=True)
        return plan

    info = init_environment(force=force, key_type=key_type)
    cfg_data = _load_config(info["config_path"])
    cfg_data["installed_version"] = version
    cfg_data["install_mode"] = "editable" if repo_path else "package"
    if repo_path:
        cfg_data["repo_path"] = repo_path
    cfg_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_config(cfg_data, info["config_path"])

    service_rc = None
    if with_service:
        service_rc = service.install(service_cfg or service.ServiceConfig(), start=True, dry_run=False)

    return {
        **info,
        "version": version,
        "install_mode": cfg_data["install_mode"],
        "repo_path": repo_path,
        "service_installed": with_service and service_rc == 0,
        "service_exit_code": service_rc,
    }


def _default_run(cmd: Sequence[str], cwd: Optional[str] = None) -> int:
    return subprocess.run(list(cmd), cwd=cwd, check=False, shell=False).returncode


def update_system(
    check_only: bool = False,
    dry_run: bool = False,
    restart_service: bool = True,
    runner: Optional[Runner] = None,
) -> Dict[str, Any]:
    """
    Updates ZeroTrustZone:
      - If editable git checkout: `git pull --ff-only` + `pip install -e . --no-deps`
      - Otherwise: `pip install --upgrade ztz`
      - Migrates ~/.ztz/config.json metadata
      - Refreshes the background proxy service if installed
    """
    version = get_installed_version()
    repo_path = detect_editable_repo()
    mode = "editable" if repo_path else "package"

    cmds: List[List[str]] = []
    if repo_path:
        cmds.append(["git", "-C", repo_path, "pull", "--ff-only"])
        cmds.append([sys.executable, "-m", "pip", "install", "-e", repo_path, "--no-deps"])
    else:
        cmds.append([sys.executable, "-m", "pip", "install", "--upgrade", "ztz"])

    plat = service.current_platform()
    svc_installed = os.path.exists(service.service_file(plat))

    if check_only or dry_run:
        return {
            "action": "update",
            "check_only": check_only,
            "dry_run": dry_run,
            "current_version": version,
            "install_mode": mode,
            "repo_path": repo_path,
            "commands": [" ".join(c) for c in cmds],
            "service_installed": svc_installed,
        }

    exec_cmd = runner or (lambda c: _default_run(c))
    for cmd in cmds:
        rc = exec_cmd(cmd)
        if rc != 0:
            raise RuntimeError(f"Update command failed ({rc}): {' '.join(cmd)}")

    new_version = get_installed_version()
    cfg_data = _load_config()
    if cfg_data or os.path.isdir(ZTZ_HOME):
        cfg_data["installed_version"] = new_version
        cfg_data["install_mode"] = mode
        if repo_path:
            cfg_data["repo_path"] = repo_path
        cfg_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_config(cfg_data)

    svc_updated = False
    if restart_service and svc_installed:
        rc = service.update(service.ServiceConfig())
        svc_updated = (rc == 0)

    return {
        "action": "update",
        "previous_version": version,
        "current_version": new_version,
        "install_mode": mode,
        "repo_path": repo_path,
        "service_updated": svc_updated,
    }


def uninstall_system(
    purge_keys: bool = False,
    keep_cache: bool = False,
    dry_run: bool = False,
    home_dir: str = ZTZ_HOME,
    service_uninstall_fn: Optional[Callable[[], int]] = None,
) -> Dict[str, Any]:
    """
    Removes ZeroTrustZone local state:
      - Stops & uninstalls the background proxy service if present
      - Deletes config.json, logs/, service/, and cache.db* (unless keep_cache=True)
      - Preserves ~/.ztz/keys unless purge_keys=True
    """
    plat = service.current_platform()
    svc_path = service.service_file(plat)
    svc_present = os.path.exists(svc_path)

    targets: List[str] = []
    for name in ("config.json", "logs", "service"):
        p = os.path.join(home_dir, name)
        if os.path.exists(p):
            targets.append(p)

    if not keep_cache:
        for name in ("cache.db", "cache.db-wal", "cache.db-shm"):
            p = os.path.join(home_dir, name)
            if os.path.exists(p):
                targets.append(p)

    keys_dir = os.path.join(home_dir, "keys")
    if purge_keys and os.path.exists(keys_dir):
        targets.append(keys_dir)

    if dry_run:
        return {
            "action": "uninstall",
            "dry_run": True,
            "service_will_remove": svc_present,
            "service_file": svc_path if svc_present else None,
            "paths_to_delete": targets,
            "keys_preserved": not purge_keys and os.path.exists(keys_dir),
        }

    service_removed = False
    if svc_present:
        fn = service_uninstall_fn or service.uninstall
        service_removed = (fn() == 0)

    deleted: List[str] = []
    for p in targets:
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.isfile(p):
            os.remove(p)
        deleted.append(p)

    # Remove ~/.ztz itself only if empty (i.e. keys were purged or never existed)
    home_removed = False
    if os.path.isdir(home_dir) and not os.listdir(home_dir):
        os.rmdir(home_dir)
        home_removed = True

    return {
        "action": "uninstall",
        "service_removed": service_removed,
        "deleted": deleted,
        "keys_preserved": not purge_keys and os.path.exists(keys_dir),
        "home_removed": home_removed,
    }
