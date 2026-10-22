# CLI Reference

ZeroTrustZone provides a unified, zero-trust CLI accessible via `ztz` or `zerotrustzone`.

---

### `ztz init`
Initializes the ZeroTrustZone environment, creates configuration files, and provisions the Root Authority keypair in `~/.ztz/keys`.
- `--force`: Force re-generation of authority keys and config files. Without it an existing private key is never replaced; a missing `authority_pub.pem` is rebuilt from it.
- `--type`: Keypair algorithm (`ed25519` or `rsa`, default: `ed25519`).
- `--json`: Emit configuration summary in JSON format.

```bash
ztz init
```

---

### `ztz doctor`
Runs comprehensive system health, runtime connectivity, and cryptographic security diagnostics.
- Checks Python environment & OpenSSL/Cryptography acceleration.
- Validates trust stores and loaded authority keys (`~/.ztz/keys`, `~/.zerotrustzone/keys`, `~/.ztz/trusted_keys`; plus `./keys` when `ZTZ_TRUST_LOCAL=1`).
- Probes the local Ollama service and the models directory it uses.
- Reports who answers on port 11434 at `127.0.0.1` and `::1` (`ZTZ`, `DIRECT` or closed). If the ZTZ proxy is running but another server also answers on that port, the verdict is `BYPASS_RISK`.
- Reports Attestation Cache metrics and Context Shield secret inspection rules.
- `--json`: Output full health diagnostics report in JSON format.

```bash
ztz doctor
```

---

### `ztz models`
Discovers, inspects, and attests local Ollama and GGUF models.

#### `ztz models list`
Scans local Ollama manifests and reports models, physical blob paths, sizes, container formats, and attestation status. The models directory is `$OLLAMA_MODELS`, else the Ollama desktop app's *models location* setting (Windows), else `~/.ollama/models`. A model counts as signed only when every layer Ollama loads (weights, vision projector, adapters) has a valid `.sig`.
- `--dir`: Optional custom Ollama models directory.
- `--json`: Output inventory in JSON format.

```bash
ztz models list
```

#### `ztz models sign <model_name>`
Resolves a model tag (e.g. `llama3.2`, `mistral:latest`) to the blobs Ollama loads for it and writes a detached signature (`.sig`) next to each, using the authority key. A bare name means `:latest`, exactly as in Ollama; another tag is never substituted. Namespaced and Hugging Face models are named as Ollama names them (`someuser/llama3:latest`, `hf.co/org/repo:Q4_K_M`). Every loaded layer is signed: the weights plus any vision projector or adapter.
- `--key`: Path to private signing key (defaults to your initialized Root Authority key).
- `--dir`: Optional custom Ollama models directory.
- `--json`: Output signature result in JSON format.

```bash
ztz models sign llama3.2
```

#### `ztz models inspect <model_name>`
Resolves a model tag to disk and performs structural bytecode inspection for GGUF metadata, Safetensors headers, or dangerous PyTorch pickle opcodes.
- `--json`: Output inspection report in JSON format.

```bash
ztz models inspect llama3.2
```

---

### `ztz sign <file>`
Generates a detached cryptographic signature (`<file>.sig`) for any model weight or context document.
- `--key`: Path to private PEM key (defaults to initialized Root Authority key if omitted).
- `--out`: Custom output path for the signature.

```bash
ztz sign models/qwen2.5-7b.gguf
```

---

### `ztz verify <file>`
Verifies a target file against its detached signature offline before memory allocation.
- `--sig`: Custom path to detached `.sig` (defaults to `<file>.sig`).
- `--trust-store`: Directory containing trusted public keys (defaults to the home trust roots under `~/.ztz`; `./keys` is only trusted when passed explicitly or with `ZTZ_TRUST_LOCAL=1`).
- `--no-cache`: Bypass the machine-bound instant attestation cache.
- `--json`: Output verification row in JSON format.

```bash
ztz verify models/qwen2.5-7b.gguf
```

---

### `ztz run`
Executes an AI runtime binary (`llama-cli` / `llama.cpp`) inside the ZTZ pre-flight quarantine boundary.
- `--llama-bin`: Path to the underlying runtime binary (e.g., `./llama-cli`).
- `--trust-store`: Public key directory (default: the home trust roots).
- `--no-cache`: Bypass the attestation cache and stream-hash every file.
- Attests every file llama.cpp would load (`-m`, `-f`, `--lora`, `-md`, `--mmproj`, `--system-prompt-file`, `--grammar-file`, …) and halts process startup if any fails. Remote-fetch flags (`-hf`, `-mu`, …) are refused, and so are `LLAMA_ARG_*` environment variables that could name a file or download (`LLAMA_ARG_MODEL`, `LLAMA_ARG_HF_REPO`, …).
- Split GGUF models (`-m model-00001-of-00003.gguf`): every shard must be present and signed; all are attested and pinned.
- Inputs are pinned before verification and held until the runtime exits (see the README's *Anti-TOCTOU File Pinning*).

```bash
ztz run --llama-bin ./llama-cli -m model.gguf -f prompt.txt
```

---

### `ztz proxy`
Starts the Zero-Trust Reverse Proxy Interceptor in front of Ollama (Ollama API only; LM Studio is not supported as a backend).
- `--host`: Host to bind (default: `127.0.0.1`).
- `--port`: Interceptor port (default: `11434`).
- `--upstream-port`: Real backend daemon port (default: `11435`).
- `--trust-store`: Public key directory (cascades to `~/.ztz/keys`).
- `--no-cache`: Bypass the attestation cache.
- `--log-file`: Append all output to this file instead of the console.
- Attests every request that would load a model: `/api/generate`, `/api/chat`, `/api/embed`, `/v1/*`, and any other POST naming a `model`. Management calls (`/api/show`, `/api/pull`, `/api/push`, `/api/delete`, `/api/copy`, `/api/create`) pass untouched.
- Resolves a model's files by asking the backend (`/api/show`): weights, vision projector and LoRA adapters are all attested. Unknown models, an unreachable backend, and models with no local files (cloud models) are refused.
- Redacts confidential credentials from `prompt`, `system` and `messages` (string content and the text parts of multimodal content lists) before forwarding; other message fields are kept.
- Refuses to start if another process already listens on `--port` at `127.0.0.1` or `::1` (clients there would bypass ZTZ).
- Every response carries `X-ZTZ-Proxy: 1`, which `ztz doctor` uses to tell the proxy from the backend.

```bash
ztz proxy --port 11434 --upstream-port 11435
```

---

### `ztz service install | uninstall | status`
Runs `ztz proxy` as a per-user background service that starts at login and restarts on failure. No admin rights are needed:

| Platform | Mechanism | Definition file |
| :--- | :--- | :--- |
| Linux | systemd user unit | `~/.config/systemd/user/ztz-proxy.service` |
| macOS | launchd LaunchAgent | `~/Library/LaunchAgents/com.zerotrustzone.proxy.plist` |
| Windows | Task Scheduler logon task "ZeroTrustZone Proxy" (hidden, `pythonw.exe`) | `~/.ztz/service/ztz-proxy.xml` |

- `install` accepts the proxy options `--host`, `--port`, `--upstream-port`, `--trust-store`, `--no-cache`, plus:
  - `--no-start`: register the service without starting it now.
  - `--dry-run`: print the definition file and the commands; change nothing.
- Output goes to `~/.ztz/logs/proxy.log`.
- Your backend's configuration is not changed: move Ollama to the upstream port yourself (`OLLAMA_HOST=127.0.0.1:11435`) and restart it.
- `status` exits `3` when the service is not installed.

```bash
ztz service install --dry-run
ztz service install
```

---

### `ztz inspect-model <file>`
Inspects GGUF, Safetensors, or PyTorch Pickle files on disk for structural risks, header integrity, and bytecode vulnerabilities.
- `--json`: Emit inspection verdict and metadata in JSON.

```bash
ztz inspect-model weights.gguf --json
```

---

### `ztz context-scan <target>`
Scans text strings, prompt files, or standard input (`-`) for leaked API keys, tokens, database URIs, or private keys.
- `--out`: Write scrubbed/sanitized text to output file.
- `--json`: Emit audit findings and SHA-256 digest in JSON format.

```bash
ztz context-scan "Run prompt with AWS key AKIAIOSFODNN7EXAMPLE" --out clean.txt
cat confidential_prompt.txt | ztz context-scan - --json
```

---

### `ztz fingerprint`
Displays the anonymous, deterministic hardware fingerprint hash bound to this physical machine.

```bash
ztz fingerprint
```

---

### `ztz cache clear`
Purges the instant hardware-bound SQLite attestation cache.

```bash
ztz cache clear
```
