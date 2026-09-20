# UserShield 🛡️

**Offline-First Zero-Trust Cryptographic Pre-Flight Firewall for Local AI Runtimes**

UserShield intercepts local LLM execution (e.g. `llama.cpp`, Ollama, ONNX runtimes) **before** model weights and prompt contexts are mapped into RAM/VRAM. By enforcing asymmetric cryptographic verification with zero network dependencies, UserShield ensures that tampered GGUF weights, backdoored system prompts, or un-attested context files cannot contaminate hardware memory registers.

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                       USERSHIELD — PRE-FLIGHT GATEWAY                        ║
║                  Zero-Trust Hardware Attestation Sentinel                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Key Invariants

1. **Pre-Memory Quarantine**: Runs mathematically strictly before `llama.cpp` allocates tensors. If verification fails, pointers are never created and execution halts instantly.
2. **100% Offline Math**: Signature validation only requires asymmetric cryptography (`Ed25519` / `RSA-PSS`) and pre-loaded public keys. Zero telemetry, zero external network queries.
3. **Multi-Gigabyte Streaming Verification**: Computes SHA-256 digests in chunks, enabling instant verification of 50GB+ GGUF weights without exhausting system memory.
4. **Air-Gapped Machine-Bound Licensing**: Prosumer ($0.99 one-time) licenses bind cryptographically to irreversible local hardware identifiers without leaking machine metrics.

---

## Architectural Workflow

```
   [ Local Weights (.gguf) / Context (.txt) ] ──► [ Detached Signature (.sig) ]
                                                            │
                                                            ▼
                                               ┌─────────────────────────┐
                                               │   UserShield Pre-Flight │
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

### 4. Run `llama.cpp` under UserShield Protection
```bash
usershield run --llama-bin ./llama-cli -m models/qwen2.5-7b-instruct-q4_k_m.gguf -f prompt.txt --ctx-size 4096
```
If any input file lacks a valid `.sig` or has been tampered with by even a single bit, UserShield terminates the process with a critical Deen-styled lockdown banner before `llama-cli` starts.

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
UserShield Core is licensed under the Apache License, Version 2.0.
