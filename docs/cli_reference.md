# CLI Reference

UserShield provides a comprehensive CLI accessible via `usershield` or `ztz`.

### `usershield sign <file>`
Generates a detached signature (`.sig`) for a target file.
- `--key`: Path to your private PEM key.
- `--algo`: Algorithm to use (default: `Ed25519`).

### `usershield verify <file>`
Verifies a target file against its detached signature offline.
- `--trust-store`: Directory containing trusted public keys (default: `./keys`).

### `usershield run`
Executes an AI runtime under ZTZ protection.
- `--llama-bin`: Path to the underlying runtime binary (e.g., `./llama-cli`).
- Passes all subsequent arguments directly to the runtime, but only *after* pre-flight checks pass.

### `usershield proxy`
Starts the Zero-Trust Reverse Proxy.
- `--port`: Local port to bind the proxy to (e.g., 11434).
- `--upstream-port`: Target backend port (e.g., 11435).

### `usershield inspect-model <file>`
Scans GGUF, Safetensors, or PyTorch Pickle files for structural risks and bytecode vulnerabilities before execution.
