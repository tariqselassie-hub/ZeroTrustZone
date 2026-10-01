# ZTZ 🛡️

**Offline-First Zero-Trust Cryptographic Pre-Flight Firewall for Local AI Runtimes**

ZTZ intercepts local LLM execution (e.g. `llama.cpp`, Ollama, ONNX runtimes) **before** model weights and prompt contexts are mapped into RAM/VRAM. By enforcing asymmetric cryptographic verification with zero network dependencies, ZTZ ensures that tampered GGUF weights, backdoored system prompts, or un-attested context files cannot contaminate hardware memory registers.

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                       ZTZ — PRE-FLIGHT GATEWAY                        ║
║                  Zero-Trust Hardware Attestation Sentinel                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Key Invariants

1. **Pre-Memory Quarantine**: Runs mathematically strictly before `llama.cpp` or Ollama allocates tensors. If verification fails, pointers are never created and execution halts instantly.
2. **Anti-TOCTOU File Locking**: Acquires mandatory OS-level shared locks (`fcntl`) before reading metadata to prevent race conditions where malicious processes swap files post-verification.
3. **100% Offline Math**: Signature validation only requires asymmetric cryptography (`Ed25519` / `RSA-PSS`) and pre-loaded public keys. Zero telemetry, zero external network queries.
4. **Multi-Gigabyte Streaming Verification**: Computes SHA-256 digests in chunks, enabling instant verification of 50GB+ GGUF weights without exhausting system memory.
5. **Machine-Bound O(1) Cache (Pro)**: First loads stream entirely; subsequent loads hit an SQLite cache cryptographically bound to your hardware fingerprint via HMAC, reducing 30-second verification times to <50ms.

---

## Architectural Workflow

```
   [ Local Weights (.gguf) / Context (.txt) ] ──► [ Detached Signature (.sig) ]
                                                            │
                                                            ▼
                                               ┌─────────────────────────┐
                                               │   ZTZ Pre-Flight │
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
git clone https://github.com/your-org/usershield.git
cd usershield

# Install locally in editable mode
pip install -e .
```

---

## Quickstart Guide

### 1. Generate an Authority Keypair (Ed25519)
```bash
usershield keygen --out-dir ./keys --name my_authority
```
This generates:
- `./keys/my_authority_priv.pem` (Keep protected!)
- `./keys/my_authority_pub.pem` (Distribute to users / trust store)

### 2. Sign Model Weights or Context Payloads
```bash
usershield sign models/qwen2.5-7b-instruct-q4_k_m.gguf --key ./keys/my_authority_priv.pem
```
Generates detached signature: `models/qwen2.5-7b-instruct-q4_k_m.gguf.sig`.

### 3. Verify Files Offline
```bash
usershield verify models/qwen2.5-7b-instruct-q4_k_m.gguf --trust-store ./keys
```

### 4. Run `llama.cpp` under ZTZ Protection
```bash
usershield run --llama-bin ./llama-cli -m models/qwen2.5-7b-instruct-q4_k_m.gguf -f prompt.txt --ctx-size 4096
```
If any input file lacks a valid `.sig` or has been tampered with by even a single bit, ZTZ terminates the process with a critical lockdown banner before `llama-cli` starts.

### 5. Start the Zero-Trust Reverse Proxy (Pro Tier)
To protect GUI apps like Open WebUI, LM Studio, or Cursor without changing their config, launch the ZTZ Interceptor on the default Ollama port:
```bash
usershield proxy --port 11434 --upstream-port 11435
```
ZTZ transparently parses incoming OpenAI/Ollama OCI generation requests, physically locates the GGUF blobs on disk, and enforces cryptographic attestation before yielding the TCP stream to the runtime.

### 6. Inspect Model Weights for Bytecode & Structural Risks
Inspect containers (GGUF, Safetensors, and legacy PyTorch `.pt`/`.bin` pickle archives) before loading:
```bash
usershield inspect-model models/qwen2.5-7b-instruct-q4_k_m.gguf
```
If legacy PyTorch pickle opcodes (`cos`, `cposix`, etc.) are detected, UserShield raises a `CRITICAL` risk alert warning of potential Arbitrary Code Execution (RCE).

### 7. Pre-Flight Context Scanning & Secret Scrubbing
Neutralize credentials, API keys (OpenAI, Anthropic, AWS, GitHub), and SSH/PGP private keys before feeding prompts into inference engines:
```bash
usershield context-scan "Analyze this deployment with sk-ant-api03-..." --out sanitized_prompt.txt
```

### 8. Manage the Instant Attestation Cache
UserShield maintains a hardware-bound SQLite cache with Windows NTFS FileIndex and POSIX inode stability to make warm loads instantaneous (<50ms). To manually purge it:
```bash
usershield cache clear
```

---

## Python SDK & Dual-Namespace Support

UserShield can be imported as either `usershield` or `ztz`:

```python
# Import via usershield namespace
from usershield.core import PreFlightValidator, ContextShield, ModelFormatInspector
from usershield.core.crypto import UserShieldSigner, UserShieldVerifier

# Inspect weights container
verdict = ModelFormatInspector.inspect("models/weights.gguf")
print(f"Format: {verdict.format}, Low Risk: {verdict.is_safe}")

# Sanitize context and prompts
result = ContextShield.sanitize("System prompt containing confidential tokens...")
clean_prompt = result.clean_text

# Pre-flight validate model and context before inference
validator = PreFlightValidator(trust_store_dir="./keys", enforce_all=True)
audit = validator.validate_bundle(
    model_path="models/weights.gguf",
    context_paths=["prompts/system.txt"]
)
assert audit.all_passed, "Quarantined! Untrusted model or context detected."
```

---

## Dual-Tier & Licensing Model

| Feature | Community (FOSS) | Pro / Power User ($19-$29) | Enterprise ($15-$30/mo/seat) |
| :--- | :--- | :--- | :--- |
| **Inference Gate** | `llama.cpp` CLI wrapper | **Ollama / LM Studio API Proxy** | gRPC / Remote Sockets |
| **Verification** | Full SHA-256 stream | **Instant Merkle / Inode Cache** | Cosign / Sigstore Integration |
| **Key Management** | Local folder drops | HF Auto-Sign & Fetch | Centralized IAM / KMS |
| **Monitoring** | Manual Execution | Background Model Daemon | Central SIEM Audit Logging |
| **Developer SDK** | None | Python `@usershield.guard` | CI/CD Build Pipelines |

To view your local machine's anonymous hardware fingerprint (for Pro licensing):
```bash
usershield fingerprint
```

---

## License
ZTZ Core is licensed under the Apache License, Version 2.0.
