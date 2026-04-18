Yes — using Ollama locally. I'll rewrite it to call your local Ollama instance directly, no internet needed.

**100% offline, zero internet dependency.** Everything runs through your local Ollama.

---

**One-time setup — enable CORS in Ollama (required for browser → Ollama calls):**

```bash
# Stop current ollama container
docker stop ollama

# Restart with CORS allowed (add to docker-compose.yml environment)
environment:
  - OLLAMA_HOST=0.0.0.0:11434
  - OLLAMA_ORIGINS=*          # ← add this line
  - OLLAMA_KEEP_ALIVE=1h
  - OLLAMA_NUM_CTX=1024
```

```bash
docker compose up -d ollama
```

Then open `codeshift-offline.html` directly in your browser — no server needed.

---

**Features:**

| Feature | Detail |
|---|---|
| **Zero internet** | Only talks to `localhost:11434` |
| **Auto model detection** | Fetches your installed models on load |
| **Smart model sort** | Prefers code-capable models (mistral, codellama, phi3, deepseek) |
| **Live streaming** | Output types in real-time as Ollama generates |
| **Config modal** | Click the connection indicator to change Ollama host |
| **Persistent settings** | Saves host URL and preferred model in localStorage |
| **28 languages** | Bash, C, C++, Java, Perl, Python, Go, Rust, JS, TS, HTML, CSS, JSON, YAML, SQL + more |
| **5 sample scripts** | Bash, C, Python, Perl, Java built-in |
| **Dependency detection** | Extracts required libs from converted output |
| **Download** | Save converted file or both files with correct extensions |
| **Ctrl+Enter** | Keyboard shortcut to convert |
