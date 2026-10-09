# Architecture

ZeroTrustZone (ZTZ) employs a multi-layered defense-in-depth architecture.

## 1. Cryptographic Pre-Flight
Before yielding the CPU/GPU to an AI process (like `llama.cpp`), ZTZ streams the target binaries and model weights through an Ed25519 or RSA-PSS signature verification sequence. If a single bit is altered, the execution is hard-terminated before the target process can load the malicious bytecode.

## 2. Machine-Bound SQLite Cache
To avoid the 30+ second latency of computing SHA-256 on a 10GB+ GGUF file on every run, ZTZ caches verification states locally. 
The cache row is **cryptographically bound** to the local hardware fingerprint, making it impossible for an attacker to spoof the SQLite cache from another machine.

## 3. Context Shield & ZTZ Enclave
The **Context Shield** intercepts prompts and system contexts. It uses regex-based heuristics to identify and strip sensitive tokens (API keys, passwords, etc.).
Once sanitized, the context payload is hashed, and a request is sent to the **ZTZ Enclave (Port 5555)** to receive a hardware-attested **ZTZ DSA Signature**.
If the enclave is offline, ZTZ falls back to a **Local Authority Signature** (`LOCAL_AUTHORITY_SIG`): the payload digest is signed with the local authority private key (`ZTZ_SEAL_KEY`, else the key from `ztz init`), and anyone holding the matching public key can check it with `ContextShield.verify_local_seal()`. If no signing key is available, the seal is reported as `UNSEALED` rather than faked.
