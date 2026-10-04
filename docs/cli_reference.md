# CLI Reference

ZeroTrustZone provides a unified, zero-trust CLI accessible via `ztz` or `zerotrustzone`.

---

### `ztz init`
Initializes the ZeroTrustZone environment, creates configuration files, and provisions the Root Authority keypair in `~/.ztz/keys`.
- `--force`: Force re-generation of authority keys and config files.
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
- Probes local Ollama / LM Studio daemons and storage directories.
- Reports Attestation Cache metrics and Context Shield secret inspection rules.
- `--json`: Output full health diagnostics report in JSON format.

```bash
ztz doctor
```

---

### `ztz models`
Discovers, inspects, and attests local Ollama and GGUF models.

#### `ztz models list`
Scans local Ollama manifests (`~/.ollama/models` or `$OLLAMA_MODELS`) and reports models, physical blob paths, sizes, container formats, and attestation status.
- `--dir`: Optional custom Ollama models directory.
- `--json`: Output inventory in JSON format.

```bash
ztz models list
```

#### `ztz models sign <model_name>`
Resolves a model tag (e.g. `llama3.2`, `mistral:latest`) to its physical blob on disk and generates a detached cryptographic signature (`.sig`) using the authority key in one step.
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
- Automatically intercepts `-m`/`--model` and `-f`/`--file` arguments and halts process startup if attestation fails.

```bash
ztz run --llama-bin ./llama-cli -m model.gguf -f prompt.txt
```

---

### `ztz proxy`
Starts the Zero-Trust Reverse Proxy Interceptor in front of Ollama or LM Studio.
- `--host`: Host to bind (default: `127.0.0.1`).
- `--port`: Interceptor port (default: `11434`).
- `--upstream-port`: Real backend daemon port (default: `11435`).
- `--trust-store`: Public key directory (cascades to `~/.ztz/keys`).
- Pre-flight attests weights and redacts confidential credentials from prompts on `/api/generate`, `/api/chat`, and OpenAI `/v1/chat/completions`.

```bash
ztz proxy --port 11434 --upstream-port 11435
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
ztz context-scan "Run prompt with sk-ant-api03-..." --out clean.txt
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
