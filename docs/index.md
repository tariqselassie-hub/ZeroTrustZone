# UserShield (ZTZ) Documentation

Welcome to the UserShield documentation. UserShield (also known as ZTZ - Zero Trust Zone) is an offline-first cryptographic pre-flight firewall for local AI weights and context payloads.

## Table of Contents
1. [Architecture Overview](architecture.md)
2. [CLI Reference](cli_reference.md)

## Core Concepts

UserShield intercepts AI execution flows to cryptographically guarantee that:
- **Model Weights** (`.gguf`, `.safetensors`, `.bin`) have not been tampered with or replaced by malicious actors.
- **Context Payloads** (prompts) are scrubbed of secrets, API keys, and sensitive data *before* they are sent to the execution environment.

It operates entirely offline with an instantaneous machine-bound SQLite cache to ensure sub-millisecond overhead after the initial stream verification.

## Quick Start
```bash
# 1. Sign your model offline
usershield sign models/model.gguf --key ./keys/private.pem

# 2. Run the model under Zero-Trust protection
usershield run --llama-bin ./llama-cli -m models/model.gguf
```
