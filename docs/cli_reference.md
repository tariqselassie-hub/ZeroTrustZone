# CLI Reference

UserShield provides a unified, zero-trust CLI accessible interchangeably via `usershield` or `ztz`.

---

### `usershield init`
Initializes the UserShield environment, creates configuration files, and provisions the Root Authority keypair in `~/.usershield/keys`.
- `--force`: Force re-generation of authority keys and config files.
- `--type`: Keypair algorithm (`ed25519` or `rsa`, default: `ed25519`).
- `--json`: Emit configuration summary in JSON format.

```bash
usershield init
```

---

### `usershield doctor`
Runs comprehensive system health, runtime connectivity, and cryptographic security diagnostics.
- Checks Python environment & OpenSSL/Cryptography acceleration.
- Validates trust stores and loaded authority keys (`./keys`, `~/.usershield/keys`).
- Probes local Ollama / LM Studio daemons and storage directories.
- Reports Attestation Cache metrics and Context Shield secret inspection rules.
- `--json`: Output full health diagnostics report in JSON format.

```bash
usershield doctor
```

---

### `usershield models`
Discovers, inspects, and attests local Ollama and GGUF models.

#### `usershield models list`
Scans local Ollama manifests (`~/.ollama/models` or `$OLLAMA_MODELS`) and reports models, physical blob paths, sizes, container formats, and attestation status.
- `--dir`: Optional custom Ollama models directory.
- `--json`: Output inventory in JSON format.

```bash
usershield models list
```

#### `usershield models sign <model_name>`
Resolves a model tag (e.g. `llama3.2`, `mistral:latest`) to its physical blob on disk and generates a detached cryptographic signature (`.sig`) using the authority key in one step.
- `--key`: Path to private signing key (defaults to your initialized Root Authority key).
- `--dir`: Optional custom Ollama models directory.
- `--json`: Output signature result in JSON format.

```bash
usershield models sign llama3.2
```

#### `usershield models inspect <model_name>`
Resolves a model tag to disk and performs structural bytecode inspection for GGUF metadata, Safetensors headers, or dangerous PyTorch pickle opcodes.
- `--json`: Output inspection report in JSON format.

```bash
usershield models inspect llama3.2
```

---

### `usershield sign <file>`
Generates a detached cryptographic signature (`<file>.sig`) for any model weight or context document.
- `--key`: Path to private PEM key (defaults to initialized Root Authority key if omitted).
- `--out`: Custom output path for the signature.

```bash
usershield sign models/qwen2.5-7b.gguf
```

---

### `usershield verify <file>`
Verifies a target file against its detached signature offline before memory allocation.
- `--sig`: Custom path to detached `.sig` (defaults to `<file>.sig`).
- `--trust-store`: Directory containing trusted public keys (cascades automatically across `./keys` and `~/.usershield/keys`).
- `--no-cache`: Bypass the machine-bound instant attestation cache.
- `--json`: Output verification row in JSON format.

```bash
usershield verify models/qwen2.5-7b.gguf
```

---

### `usershield run`
Executes an AI runtime binary (`llama-cli` / `llama.cpp`) inside the ZTZ pre-flight quarantine boundary.
- `--llama-bin`: Path to the underlying runtime binary (e.g., `./llama-cli`).
- Automatically intercepts `-m`/`--model` and `-f`/`--file` arguments and halts process startup if attestation fails.

```bash
usershield run --llama-bin ./llama-cli -m model.gguf -f prompt.txt
```

---

### `usershield proxy`
Starts the Zero-Trust Reverse Proxy Interceptor in front of Ollama or LM Studio.
- `--host`: Host to bind (default: `127.0.0.1`).
- `--port`: Interceptor port (default: `11434`).
- `--upstream-port`: Real backend daemon port (default: `11435`).
- `--trust-store`: Public key directory (cascades to `~/.usershield/keys`).
- Pre-flight attests weights and redacts confidential credentials from prompts on `/api/generate`, `/api/chat`, and OpenAI `/v1/chat/completions`.

```bash
usershield proxy --port 11434 --upstream-port 11435
```

---

### `usershield inspect-model <file>`
Inspects GGUF, Safetensors, or PyTorch Pickle files on disk for structural risks, header integrity, and bytecode vulnerabilities.
- `--json`: Emit inspection verdict and metadata in JSON.

```bash
usershield inspect-model weights.gguf --json
```

---

### `usershield context-scan <target>`
Scans text strings, prompt files, or standard input (`-`) for leaked API keys, tokens, database URIs, or private keys.
- `--out`: Write scrubbed/sanitized text to output file.
- `--json`: Emit audit findings and SHA-256 digest in JSON format.

```bash
usershield context-scan "Run prompt with sk-ant-api03-..." --out clean.txt
cat confidential_prompt.txt | usershield context-scan - --json
```

---

### `usershield fingerprint`
Displays the anonymous, deterministic hardware fingerprint hash bound to this physical machine.

```bash
usershield fingerprint
```

---

### `usershield cache clear`
Purges the instant hardware-bound SQLite attestation cache.

```bash
usershield cache clear
```
