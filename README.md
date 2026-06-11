<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Semgrep-Powered-orange?style=for-the-badge" alt="Semgrep">
  <img src="https://img.shields.io/badge/LLM-GPT--4o%20|%20Gemini-purple?style=for-the-badge" alt="LLM">
</p>

<h1 align="center">
  <img src="assets/logo.png" alt="AutoSAST Logo" width="42" style="vertical-align: middle;">
  AutoSAST
</h1>

<p align="center">
  <strong>Stop drowning in false positives. Fix the real vulnerabilities quickly.</strong>
</p>

<p align="center">
  <em>AI-Powered Static Analysis Triage that thinks like a security engineer.</em>
</p>

---

## The Problem

You ran Semgrep. Now you're staring at **hundreds of findings**.

Half of them look like this:
```
⚠️  SQL Injection in AccountHandler.java:32
⚠️  SQL Injection in SecureReportHandler.java:37  ← Actually sanitized upstream
⚠️  SQL Injection in SecureReportHandler.java:54  ← Also sanitized
⚠️  XSS in AdminController.java:30
⚠️  Weak Crypto in HashUtil.java:14               ← Dead code, never called
```

Sound familiar?

> **Are you sitting on a haystack of false positives?**

You spend hours manually reviewing findings, tracing data flows, checking for sanitization—only to discover most alerts are noise. Meanwhile, the *real* vulnerabilities slip through because you're drowning in false positives.

**What if your SAST tool could think?**

---

## The Solution

**AutoSAST** is an intelligent agent that investigates each finding like a **senior security engineer** would:

- 📖 **Reads the code** — not just the flagged line, but callers, callees, and cross-file dependencies
- 🔍 **Traces data flow** — follows tainted variables through functions and across file boundaries  
- ✅ **Checks sanitization** — detects 60+ sanitization patterns (SQL, XSS, SSRF, Path Traversal)
- 🧠 **Reasons about context** — understands when parameterized queries, encoding, or validation makes a finding safe

The result? **60%+ false positive reduction** with **100% accuracy** on verified testbeds.

---

## ⚡ Quick Start

```bash
# Install
pip install -r requirements.txt

# Configure (choose your LLM provider)
export OPENAI_API_KEY=sk-...
# or export GEMINI_API_KEY=...

# Run
python -m src.cli scan /path/to/your/code
```

That's it. **No complex setup. No training. No configuration files.**

---

## 🎯 Real Results

From an actual scan on a Java codebase:

| Metric | Before AutoSAST | After AutoSAST |
|--------|-------------|------------|
| **Findings** | 5 alerts | 2 actionable |
| **Time Spent** | Hours of triage | Seconds |
| **False Positives** | Unknown | 0 |
| **Reduction** | — | **60%** |

```
✅ TRUE POSITIVE  AccountHandler.java:32      SQL Injection (unsanitized input)
✅ TRUE POSITIVE  AdminController.java:30     XSS (direct response writer)
❌ FALSE POSITIVE SecureReportHandler.java:37 Sanitized via SecurityUtils.sanitizeForSql()
❌ FALSE POSITIVE SecureReportHandler.java:54 Sanitized via SecurityUtils.sanitizeForSql()
❌ FALSE POSITIVE HashUtil.java:14            Dead code - function never called
```

---

## How It Works

<p align="center">
  <img src="assets/demo.gif" alt="AutoSAST Demo" width="600">
</p>

```
Your Code → Semgrep Scan → 5 Findings → ⚡ AutoSAST Agent → 2 Real Vulnerabilities
                                              ↓
                                    (traces data flow,
                                     checks sanitization,
                                     reasons about context)
```

The agent **iteratively investigates** each finding:

1. **Extract context** — Pull relevant code from the flagged location
2. **Ask guided questions** — Is input sanitized? Is PreparedStatement used?
3. **Call tools on demand** — Request more code, trace callers, search for patterns
4. **Render verdict** — TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_REVIEW

---

## ✨ Features

### 🛡️ Inter-Procedural Data Flow Analysis
Traces tainted variables **across functions and files**. Because sanitization often happens in a utility class, not at the sink.

### 🔍 Dynamic Context Retrieval  
The LLM **reads your codebase on demand**—callers, callees, definitions, references. It sees what it needs, exactly when it needs it.

### 🧹 Sanitization Detection
Recognizes **60+ sanitization patterns** across categories:
- SQL: `PreparedStatement`, `setString()`, parameterized queries, ORM patterns
- XSS: OWASP Encoder, `escapeHtml`, `StringEscapeUtils`
- Path Traversal: `normalize()`, `getCanonicalPath()`
- Command Injection: `ProcessBuilder` arrays, allowlists
- And many more...

### 🌐 Multi-Language Support
Full analysis support for:
- **Java** — Servlets, Spring, JDBC, Hibernate
- **Python** — Flask, Django, SQLAlchemy
- **JavaScript/TypeScript** — Express, Node.js, React

### 🧠 Agentic Reasoning
Not a simple classifier. An **actual agent** that:
- Uses tools iteratively to gather evidence
- Follows caller chains to entry points  
- Understands framework conventions
- Provides detailed reasoning for each verdict

---

## 🛠️ CLI Commands

```bash
# Scan a local codebase
python -m src.cli scan /path/to/project

# Scan a GitHub/GitLab repository (auto-clones and cleans up)
python -m src.cli scan https://github.com/user/repository
python -m src.cli scan https://github.com/user/repo --branch develop

# Scan with custom output path
python -m src.cli scan . -o my-custom-report.json

# Scan with detailed per-finding analysis
python -m src.cli scan . --detailed-output

# View previous results
python -m src.cli view results/scan_project_20260611_143022.json

# Inspect context extraction for a specific finding
python -m src.cli context src/Handler.java 42
```

**Note:** Results are automatically saved to the `results/` folder with naming convention:
`scan_<target>_<timestamp>.json` (e.g., `scan_myproject_20260611_143022.json`)

---

## ⚙️ Configuration

Configure via environment variables or `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `PROVIDER` | LLM Provider (`openai`, `azure`, `gemini`) | `openai` |
| `MODEL` | Model name (e.g., `gpt-4o`, `gemini-1.5-pro`) | `gpt-4o` |
| `OPENAI_API_KEY` | API key for OpenAI | — |
| `GEMINI_API_KEY` | API key for Google Gemini | — |

---

## 🧰 Agent Tools

AutoSAST's LLM agent has access to powerful code analysis tools:

| Tool | Purpose |
|------|---------|
| `get_function_code` | Retrieve full source of any function/method |
| `get_caller_chain` | Trace backwards to find all callers up to entry points |
| `analyze_data_flow` | Inter-procedural taint tracking from source to sink |
| `get_sanitization_check` | Detect sanitization applied to a variable |
| `search_codebase` | Find patterns, security utilities, or similar code |
| `get_imports` | Understand available libraries and frameworks |
| `map_arguments` | Track data flow between caller and callee |

---

## 📊 Benchmarks

Tested on internal ground truth testbed:

| Metric | Value |
|--------|-------|
| **Accuracy** | 100% (15/15 correct classifications) |
| **False Positive Reduction** | 60%+ |
| **Avg. Tool Calls per Finding** | 3.4 |
| **Cross-File Refs Resolved** | 36 |

---

## 🚀 Why AutoSAST?

| Without AutoSAST | With AutoSAST |
|-------------|-----------|
| Hours of manual triage | Seconds of automated analysis |
| Alert fatigue → missed vulns | Focus on what matters |
| "I'll check it later" → never | Immediate, confident verdicts |
| Tribal knowledge required | Reasoning is documented |

---

## 🗺️ Roadmap

- [x] Java, Python, JS/TS support
- [x] Inter-procedural data flow
- [x] GPT-4o & Gemini support
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] IDE extensions (VS Code, IntelliJ)
- [ ] Custom rule support
- [ ] Auto-fix suggestions

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Stop wasting time on false positives.</strong><br>
  <em>Let AutoSAST do the triage. You focus on fixing real vulnerabilities.</em>
</p>

<p align="center">
  <a href="#-quick-start">Get Started →</a>
</p>
