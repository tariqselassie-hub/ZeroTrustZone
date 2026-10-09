# ZeroTrustZone (ZTZ) 🛡️

[![CI](https://github.com/tariqselassie-hub/ZeroTrustZone/actions/workflows/ci.yml/badge.svg)](https://github.com/tariqselassie-hub/ZeroTrustZone/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-available-brightgreen.svg)](docs/index.md)

**Offline-First Zero-Trust Cryptographic Pre-Flight Firewall for Local AI Runtimes**

> 📖 **Full documentation is available in the [`docs/` folder](docs/index.md).**

ZTZ intercepts local LLM execution (`llama.cpp` via `ztz run`, Ollama / LM Studio via `ztz proxy`, and in-process runtimes such as ONNX Runtime, Safetensors or PyTorch via the Python SDK) **before** model weights and prompt contexts are mapped into RAM/VRAM. By enforcing asymmetric cryptographic verification with zero network dependencies, ZTZ ensures that tampered GGUF weights, backdoored system prompts, or un-attested context files cannot contaminate hardware memory registers.

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                       ZTZ — PRE-FLIGHT GATEWAY                               ║
║                  Zero-Trust Hardware Attestation Sentinel                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Key Invariants

1. **Pre-Memory Quarantine**: Runs mathematically strictly before `llama.cpp` or Ollama allocates tensors. If verification fails, pointers are never created and execution halts instantly.
2. **Anti-TOCTOU File Pinning**: `ztz run` and the SDK's `attested` / `@guard` pin every input file *before* verification and hold it until the runtime exits (or the SDK block ends), so the bytes loaded are the bytes attested.
   - **Windows**: mandatory. Files are opened read-share-only, so the OS refuses any other process's attempt to write, rename or delete them. If another process already has a file open for writing, ZTZ aborts instead of verifying.
   - **Linux/macOS**: advisory shared `flock`. This only stops processes that also take locks.
3. **100% Offline Math**: Signature validation only requires asymmetric cryptography (`Ed25519` / `RSA-PSS`) and pre-loaded public keys. Zero telemetry, zero external network queries.
4. **Multi-Gigabyte Streaming Verification**: Computes SHA-256 digests in chunks, enabling instant verification of 50GB+ GGUF weights without exhausting system memory.
5. **Machine-Bound O(1) Cache (Pro)**: First loads stream entirely; subsequent loads hit an SQLite cache whose rows are HMAC-bound to your hardware fingerprint, the exact `.sig` bytes, and the signing authority's public key, reducing 30-second verification times to <50ms. Replacing a signature or removing a key from the trust store invalidates the cached result immediately.

---

## Architectural Workflow

```
   [ Local Weights (.gguf) / Context (.txt) ] ──► [ Detached Signature (.sig) ]
                                                            │
                                                            ▼
                                               ┌─────────────────────────┐
                                               │   ZTZ Pre-Flight        │
                                               │  (Zero RAM/Tensor Alloc)│
                                               └────────────┬────────────┘
                                                            │
                                   ┌─────────────────────────┴─────────────────────────┐
                                   │                                                   │
                               [ Valid ]                                           [ Invalid ]
                                   ▼                                                   ▼
                      ┌─────────────────────────┐                         ╔═════════════════════════╗
                      │ llama.cpp Process Exec  │                         ║  CRITICAL HARD ISOLATION║
                      │  (Memory Allocation OK) │                         ║   Execution Terminated  ║
                      └─────────────────────────┘                         ╚═════════════════════════╝
```

---

## Installation

```bash
# Clone the standalone repository
git clone https://github.com/tariqselassie-hub/ZeroTrustZone.git
cd ZeroTrustZone

# Install locally in editable mode
pip install -e .
```

---

## Quickstart Guide

### 1. Initialize ZeroTrustZone (1-Step Setup)
```bash
ztz init
```
Automatically provisions your root authority keypair (`authority_priv.pem` and `authority_pub.pem`) and installs the global trust store in `~/.ztz/keys`. ZTZ now works seamlessly across any folder.

> **Trust roots:** by default ZTZ trusts public keys only from `~/.ztz/keys`, `~/.zerotrustzone/keys` and `~/.ztz/trusted_keys`. A `./keys` folder in the current directory is **not** trusted automatically (a downloaded model folder could ship its own key). Opt in per command with `--trust-store ./keys`, or globally with `ZTZ_TRUST_LOCAL=1`.

### 2. Verify System Health & Runtime Diagnostics
```bash
ztz doctor
```
Audits your cryptography engine, loaded keys, cache health, and automatically detects running Ollama / LM Studio instances.

### 3. Discover & Sign Local Ollama Models in 1 Step
```bash
# View all installed models and their attestation status
ztz models list

# Automatically resolve and sign an Ollama model tag
ztz models sign llama3.2

# Structural container inspection for bytecode / pickle risks
ztz models inspect llama3.2
```

### 4. Verify Any File or Model Offline
```bash
ztz verify models/qwen2.5-7b-instruct-q4_k_m.gguf
```

### 5. Start the Zero-Trust Reverse Proxy (Pro Tier)
To protect GUI apps like Open WebUI, LM Studio, or Cursor without changing their config, launch the ZTZ Interceptor on the default Ollama port:
```bash
ztz proxy --port 11434 --upstream-port 11435
```
ZTZ transparently intercepts incoming OpenAI/Ollama OCI generation requests, physically locates the GGUF blobs on disk, and enforces cryptographic attestation before yielding the TCP stream to the runtime. Prompts and chat messages are scrubbed of secrets on the way through, and each request carries `X-ZTZ-Enclave-Seal` / `X-ZTZ-Enclave-Status` headers (plus `X-ZTZ-Digest` for `prompt` requests) describing its attestation seal.

### 6. Run `llama.cpp` under Pre-Flight Protection
```bash
ztz run --llama-bin ./llama-cli -m models/qwen2.5-7b-instruct-q4_k_m.gguf -f prompt.txt --ctx-size 4096
```
If any input file lacks a valid `.sig` or has been tampered with by even a single bit, ZTZ terminates the process with a critical lockdown banner before `llama-cli` starts.

Every file llama.cpp would load is attested, not just `-m`/`-f`: LoRA adapters (`--lora`, `--lora-scaled`), draft/vocoder models (`-md`, `-mv`), multimodal projectors (`--mmproj`), control vectors, and context files (`--system-prompt-file`, `--grammar-file`, `--json-schema-file`, `--chat-template-file`, `-bf`). Flags that download weights at runtime (`-hf`, `-hff`, `-mu`, `--docker-repo`, `--mmproj-url`, …) are refused outright. All other arguments, including `--help`, are passed straight to the llama binary.

### 7. Pre-Flight Context Scanning & Secret Scrubbing
Neutralize credentials before feeding prompts into inference engines. Built-in rules cover PEM private keys (RSA, EC, DSA, OpenSSH, PGP), OpenAI and Anthropic API keys (including long `sk-proj-` / `sk-ant-api03-` keys, always masked in full), GitHub tokens, AWS access key IDs, Google API keys, Slack tokens, JWTs, database URIs with embedded credentials, and quoted `password=`/`api_key=`-style assignments:
```bash
ztz context-scan "Deploy with AWS key AKIAIOSFODNN7EXAMPLE" --out sanitized_prompt.txt
cat confidential_prompt.txt | ztz context-scan - --json
```

### 8. Manage the Instant Attestation Cache
ZTZ maintains a hardware-bound SQLite cache with Windows NTFS FileIndex and POSIX inode stability to make warm loads instantaneous (<50ms). To manually purge it:
```bash
ztz cache clear
```

---

## Python SDK & Dual-Namespace Support

ZeroTrustZone can be imported interchangeably as `zerotrustzone` or `ztz`. Both names resolve to the same modules, so `zerotrustzone.core.crypto is ztz.core.crypto`.

```python
from ztz.core import TrustStore, PreFlightValidator, ContextShield, ModelFormatInspector

# Inspect weights container
verdict = ModelFormatInspector.inspect("models/weights.gguf")
print(f"Format: {verdict.format}, Safe container: {verdict.is_safe_format}, Risk: {verdict.risk_level}")

# Sanitize context and prompts
result = ContextShield.sanitize("System prompt containing confidential tokens...")
clean_prompt = result.clean_text

# Pre-flight validate model and context before inference
trust_store = TrustStore()  # home trust roots; or TrustStore(["/path/to/keys"])
with PreFlightValidator(trust_store) as validator:
    all_clean, rows, elapsed = validator.audit_batch([
        "models/weights.gguf",
        "prompts/system.txt",
    ])
for row in rows:
    print(row["resource"], row["status"], row["error"] or "")
assert all_clean, "Quarantined! Untrusted model or context detected."
```

Each row's `status` is `VERIFIED` / `VERIFIED_CACHE` on success, or one of `MISSING`, `UNSAFE_FORMAT`, `NO_SIG`, `NO_ROOTS`, `TAMPERED`.

Load any in-process runtime (ONNX Runtime, Safetensors, PyTorch...) inside an attested block. The files are pinned, verified, and stay pinned until the block exits:

```python
import onnxruntime
import ztz

with ztz.attested("models/model.onnx"):
    session = onnxruntime.InferenceSession("models/model.onnx")
```

Or guard a function so its file arguments are attested and pinned while it runs:

```python
import ztz
from ztz.sdk.exceptions import UntrustedPayloadError

@ztz.guard(targets=["model_path", "context_path"])
def load(model_path: str, context_path: str):
    ...

try:
    load("models/weights.gguf", "prompts/system.txt")
except UntrustedPayloadError as e:
    print(e)
```

---

## Dual-Tier & Licensing Model

| Feature | Community (FOSS) | Pro / Power User ($19-$29) | Enterprise ($15-$30/mo/seat) |
| :--- | :--- | :--- | :--- |
| **Inference Gate** | `llama.cpp` CLI wrapper | **Ollama / LM Studio API Proxy** | gRPC / Remote Sockets |
| **Verification** | Full SHA-256 stream | **Instant Merkle / Inode Cache** | Cosign / Sigstore Integration |
| **Key Management** | Local folder drops | HF Auto-Sign & Fetch | Centralized IAM / KMS |
| **Monitoring** | Manual Execution | Background Model Daemon | Central SIEM Audit Logging |
| **Developer SDK** | None | Python `@ztz.guard` | CI/CD Build Pipelines |

To view your local machine's anonymous hardware fingerprint (for Pro licensing):
```bash
ztz fingerprint
```

---

## License
ZeroTrustZone (ZTZ Core) is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for more details. 

For information on open-source libraries used in this project, please refer to the [Third-Party Notices](THIRDPARTY.md).
