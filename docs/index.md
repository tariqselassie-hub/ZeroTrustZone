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
# 1. Initialize environment and root authority keys (1-step setup)
usershield init

# 2. Check system diagnostics and running AI daemons
usershield doctor

# 3. Discover and attest local Ollama models in 1 click
usershield models list
usershield models sign llama3.2

# 4. Run llama.cpp or protect Ollama/LM Studio via reverse proxy
usershield run --llama-bin ./llama-cli -m models/model.gguf
usershield proxy --port 11434 --upstream-port 11435
```

