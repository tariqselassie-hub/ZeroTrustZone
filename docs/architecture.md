# Architecture

ZeroTrustZone (ZTZ) employs a multi-layered defense-in-depth architecture.

## 1. Cryptographic Pre-Flight
Before yielding the CPU/GPU to an AI process (like `llama.cpp`), ZTZ streams the target binaries and model weights through an Ed25519 or RSA-PSS signature verification sequence. If a single bit is altered, the execution is hard-terminated before the target process can load the malicious bytecode.

## 2. Machine-Bound SQLite Cache
To avoid the 30+ second latency of computing SHA-256 on a 10GB+ GGUF file on every run, ZTZ caches verification states locally. 
The cache row is **cryptographically bound** to the local hardware fingerprint, making it impossible for an attacker to spoof the SQLite cache from another machine. File paths are canonicalized and normalized (`os.path.normcase(os.path.abspath(...))`) ensuring robust cache indexing across relative, redundant, and case-varied path references. On POSIX the row is also bound to the file's ctime, which userspace cannot roll back, so a same-size in-place rewrite with a restored mtime misses the cache. The fingerprint is not a secret: the cache speeds up warm loads, it is not a barrier against a process running as the same user.

## 3. Context Shield & ZTZ Enclave
The **Context Shield** intercepts prompts, system contexts, message histories, and completion suffixes before LLM ingestion. It uses an $O(N)$ single-pass, non-overlapping span-based substitution engine to detect and mask sensitive tokens (API keys, passwords, database credentials, PEM private keys, etc.) while recording exact source character offsets without string corruption.
Once sanitized, the context payload is hashed, and a request is sent to the **ZTZ Enclave (Port 5555)** to receive a hardware-attested **ZTZ DSA Signature** (with automatic loopback proxy bypass to prevent local routing stalls). The enclave URL comes from `ZTZ_ENCLAVE_URL` (default `http://127.0.0.1:5555`); if `ENCLAVE_API_TOKEN` is set it is sent as `Authorization: Bearer <token>`. ZTZ does not verify the returned `ZTZ_DSA` signature itself; consumers that rely on it must check it against the enclave's key.
If the enclave is offline, ZTZ falls back to a **Local Authority Signature** (`LOCAL_AUTHORITY_SIG`): the payload digest is signed with the local authority private key (`ZTZ_SEAL_KEY`, else the key from `ztz init`), and anyone holding the matching public key can check it with `ContextShield.verify_local_seal()`. If no signing key is available, the seal is reported as `UNSEALED` rather than faked.

## 4. Container & Bytecode Structural Inspection
Before mapping models into memory registers, ZTZ parses model container formats:
- **GGUF**: Safely reads container headers and key-value metadata streams, extracting architecture names (`general.architecture`), total parameter counts (`general.parameter_count`), context window dimensions, embedding dimensions, layer counts, and attention heads into auditable pre-flight reports.
- **Safetensors**: Validates 8-byte uint64 headers and verifies the strict absence of executable bytecode.
- **PyTorch Checkpoints**: Scans unpickling bytecode streams for malicious opcodes (`GLOBAL`, `REDUCE`, `BUILD`, `STACK_GLOBAL`) to prevent arbitrary code execution (RCE).
