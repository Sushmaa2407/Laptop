# ADR-003: LLM model
Decision: use llama3.2:3b via Ollama on the Windows host (GPU).
Context: phi3:mini spilled 13% to CPU (15 tok/s). llama3.2:3b runs 100% on GPU at about 46 tok/s and followed the 3-sentence instruction.
Consequences: cold load took about 57 s after idle. Backend must warm the model at startup, use keep_alive, and fall back to the template if it times out. Re-compare with qwen2.5:3b in Phase 6 only if quality is an issue.
