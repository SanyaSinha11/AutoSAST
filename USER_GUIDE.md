# AutoSAST User Guide

**AI-Powered Static Analysis Triage for Modern Development Teams**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Use Cases](#use-cases)
3. [Getting Started](#getting-started)
4. [Usage Scenarios](#usage-scenarios)
5. [Advanced Features](#advanced-features)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Introduction

AutoSAST is an intelligent security triage tool that dramatically reduces false positives from static analysis scanners. Instead of manually reviewing hundreds of alerts, AutoSAST uses AI to investigate findings like a senior security engineer would—tracing data flows, checking sanitization, and reasoning about context.

### Why AutoSAST?

- **Save Time**: Reduce triage time from hours to seconds
- **Improve Accuracy**: 60%+ false positive reduction with 100% accuracy on verified testbeds
- **Shift Left**: Catch real vulnerabilities early in the development lifecycle
- **Scale Security**: Enable developers to fix security issues without waiting for security team review

---

## Use Cases

### 1. 🏗️ Developer Workflow - Shift Security Left

**Scenario**: Developers want to find and fix security issues before code review.

**How to Use**:
```bash
# Before committing code
python -m src.cli scan ./src

# Review findings in interactive UI
python -m src.cli view results/scan_src_20260611_143022.json --ui
```

**Benefits**:
- Catch vulnerabilities in real-time during development
- Fix issues before they reach code review
- Learn security best practices through AI explanations
- Reduce security debt accumulation

**Typical Workflow**:
1. Developer writes code
2. Runs AutoSAST locally before `git commit`
3. Reviews 2-3 true positives (instead of 10+ raw findings)
4. Fixes real issues, ignores false positives with confidence
5. Commits clean, secure code

---

### 2. 🔄 CI/CD Pipeline Integration

**Scenario**: Automatically scan every pull request and block merges with critical vulnerabilities.

**How to Use**:
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    python -m src.cli scan . -o results.json --severity high critical
```

**Benefits**:
- Automated security gate in your pipeline
- Fail builds only on real vulnerabilities (not false positives)
- No manual intervention needed
- Consistent security standards across all code

**Integration Patterns**:
- **GitHub Actions**: Scan on every PR, comment results
- **GitLab CI**: Block merge requests with vulnerabilities
- **Jenkins**: Add security stage to existing pipelines
- **CircleCI/Azure**: Integrate seamlessly with existing workflows

**Exit Codes**:
- `0`: No critical vulnerabilities found → Pipeline continues
- `1`: Critical vulnerabilities found → Pipeline fails
- `2`: Scan error → Pipeline fails

---

### 3. 🔍 Security Team Reviews

**Scenario**: Security team needs to review findings from scheduled scans or audits.

**How to Use**:
```bash
# Run comprehensive scan
python -m src.cli scan /path/to/codebase --detailed-output

# Review with full context
python -m src.cli view results/scan_codebase_20260611.json --ui
```

**Benefits**:
- Focus on actual security issues, not noise
- Detailed AI reasoning for each finding
- Export reports for compliance documentation
- Track security improvements over time

**Review Workflow**:
1. Schedule weekly/monthly scans
2. Security team reviews AutoSAST results
3. High-confidence findings → Create tickets
4. Low-confidence findings → Manual deep-dive
5. Track metrics: reduction rate, vulnerabilities fixed

---

### 4. 📊 Security Audits & Compliance

**Scenario**: Prepare security documentation for audits, compliance checks, or vulnerability management programs.

**How to Use**:
```bash
# Scan entire codebase
python -m src.cli scan /app --detailed-output -o audit_report.json

# Generate summary statistics
python -c "
import json
with open('results/audit_report.json') as f:
    data = json.load(f)
    print(f'Total Findings: {data[\"stats\"][\"total_findings\"]}')
    print(f'True Positives: {data[\"stats\"][\"true_positives\"]}')
    print(f'False Positives Filtered: {data[\"stats\"][\"false_positives\"]}')
"
```

**Benefits**:
- Documented evidence of security testing
- Clear distinction between real and false vulnerabilities
- AI reasoning provides audit trail
- Exportable JSON reports for compliance tools

---

### 5. 🎓 Security Training & Education

**Scenario**: Help developers learn secure coding practices through real examples.

**How to Use**:
```bash
# Scan training codebase
python -m src.cli scan ./training-examples --ui

# Review AI explanations for each finding
```

**Benefits**:
- Learn from AI explanations of why something is/isn't vulnerable
- Understand data flow analysis concepts
- See real sanitization patterns in action
- Build security awareness across the team

---

## Getting Started

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/autosast.git
cd autosast

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Semgrep
pip install semgrep
# OR: brew install semgrep (macOS)
# OR: Use system package manager

# 4. Verify installation
python -m src.cli --help
```

### Configuration

AutoSAST supports multiple LLM providers. Choose one:

#### Option 1: OpenAI (Recommended)
```bash
export OPENAI_API_KEY=sk-your-key-here
export PROVIDER=openai
export MODEL=gpt-4o
```

#### Option 2: Google Gemini
```bash
export GOOGLE_API_KEY=your-key-here
export PROVIDER=gemini
export MODEL=gemini-1.5-pro
```

#### Option 3: Local Ollama (Free, Private)
```bash
# Install Ollama first: https://ollama.ai
ollama pull qwen2.5:14b

export PROVIDER=ollama
export MODEL=qwen2.5:14b
export OLLAMA_BASE_URL=http://localhost:11434
```

#### Option 4: Azure OpenAI
```bash
export AZURE_OPENAI_API_KEY=your-key
export AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/
export PROVIDER=azure
export MODEL=gpt-4o
```

#### Option 5: Groq (Fast)
```bash
export GROQ_API_KEY=your-key
export PROVIDER=groq
export MODEL=mixtral-8x7b-32768
```

### Using .env File (Recommended)

Create a `.env` file in the project root:

```bash
# .env
PROVIDER=openai
MODEL=gpt-4o
OPENAI_API_KEY=sk-your-key-here

# Optional settings
SEMGREP_PATH=semgrep
LOG_LEVEL=INFO
```

---

## Usage Scenarios

### Scenario A: Quick Local Scan

**Goal**: Scan current project before committing

```bash
# Scan current directory
python -m src.cli scan .

# Results automatically saved to: results/scan_<timestamp>.json
```

### Scenario B: Scan GitHub/GitLab Repository

**Goal**: Scan a public Git repository directly (no manual cloning needed)

```bash
# Scan GitHub repository (default branch)
python -m src.cli scan https://github.com/user/repository

# Scan specific branch
python -m src.cli scan https://github.com/user/repo --branch develop

# Scan specific tag
python -m src.cli scan https://github.com/user/repo --tag v1.0.0

# Scan specific commit
python -m src.cli scan https://github.com/user/repo --commit abc123def

# Works with GitLab, Bitbucket, and any Git URL
python -m src.cli scan https://gitlab.com/user/project
python -m src.cli scan https://bitbucket.org/user/repo
```

**Note**:
- ✅ Public repositories only (private repos show clear error message)
- ✅ Temporary directory auto-created in `./tmp/`
- ✅ Auto-cleanup after scan completes
- ✅ Supports all Git hosting platforms

### Scenario C: Scan Specific Directory

**Goal**: Scan only the src folder

```bash
python -m src.cli scan ./src -o results/src-scan.json
```

### Scenario D: Filter by Severity

**Goal**: Only check high and critical severity issues

```bash
python -m src.cli scan . --severity high critical
```

### Scenario E: Limit Findings (Testing)

**Goal**: Test configuration on first 5 findings

```bash
python -m src.cli scan . --limit 5
```

### Scenario F: View Previous Results

**Goal**: Review results from a previous scan

```bash
python -m src.cli view results/scan_20260611_143022.json --ui
```

### Scenario G: Investigate Single Finding

**Goal**: Deep-dive into a specific file/line

```bash
python -m src.cli context src/auth.py 42 --rule sql-injection
```

---

## Advanced Features

### 1. Interactive UI Mode

View scan results in a rich terminal UI:

```bash
python -m src.cli view results/scan.json --ui
```

Features:
- Color-coded verdicts (green/red/yellow)
- Detailed AI reasoning
- Confidence scores
- Tool usage statistics
- Navigation between findings

### 2. Detailed Output Mode

Get comprehensive analysis with full context:

```bash
python -m src.cli scan . --detailed-output
```

Creates additional directory with:
- Full code context for each finding
- Complete AI reasoning chains
- Tool call logs
- Debug information

### 3. Custom Semgrep Rules

Use your own Semgrep rules:

```bash
python -m src.cli scan . --semgrep-config custom-rules.yml
```

### 4. No Iterative Context (Faster)

Disable iterative context expansion for speed:

```bash
python -m src.cli scan . --no-iterative
```

Trade-off: Faster but may miss some complex data flows

### 5. JSON Output for Automation

Parse results programmatically:

```python
import json

with open('results/scan.json') as f:
    results = json.load(f)

true_positives = [
    r for r in results['analysis_results']
    if r['verdict'] == 'TRUE_POSITIVE'
]

print(f"Found {len(true_positives)} real vulnerabilities")
```

---

## Best Practices

### For Developers

1. **Run Before Committing**: Make AutoSAST part of your pre-commit workflow
2. **Start with High Severity**: Focus on critical issues first with `--severity high critical`
3. **Review AI Reasoning**: Learn from the explanations to improve secure coding
4. **Fix True Positives Immediately**: Don't accumulate security debt
5. **Share Findings**: Discuss interesting cases with the team

### For Security Teams

1. **Establish Baselines**: Run initial scans to understand your security posture
2. **Track Metrics**: Monitor reduction rates and time-to-fix
3. **Tune Thresholds**: Adjust severity filters based on team capacity
4. **Document Patterns**: Build a knowledge base of common false positives
5. **Integrate with Ticketing**: Auto-create issues for high-confidence findings

### For CI/CD

1. **Fail Fast**: Use `--severity high critical` to catch critical issues only
2. **Cache Dependencies**: Speed up pipelines by caching pip packages
3. **Parallel Scans**: Split large codebases across multiple jobs
4. **Store Artifacts**: Always upload results for debugging
5. **Incremental Scanning**: Consider scanning only changed files in PRs

---

## Troubleshooting

### Common Issues

#### "No API key found"

**Problem**: LLM provider API key is not configured

**Solution**:
```bash
# Check environment variables
echo $OPENAI_API_KEY

# Set API key
export OPENAI_API_KEY=sk-your-key

# Or create .env file
echo "OPENAI_API_KEY=sk-your-key" > .env
```

#### "Semgrep command not found"

**Problem**: Semgrep is not installed

**Solution**:
```bash
pip install semgrep
# or
brew install semgrep  # macOS
```

#### "Rate limit exceeded"

**Problem**: Hitting API rate limits

**Solution**:
- Use `--limit 10` to scan fewer findings
- Switch to different LLM provider
- Use local Ollama (no rate limits)
- Wait and retry

#### "Scan takes too long"

**Problem**: Large codebase or many findings

**Solution**:
```bash
# Limit number of findings
python -m src.cli scan . --limit 20

# Filter by severity
python -m src.cli scan . --severity critical

# Disable iterative context
python -m src.cli scan . --no-iterative

# Scan specific paths only
python -m src.cli scan ./src/auth
```

#### "Low confidence scores"

**Problem**: AI is uncertain about findings

**Solution**:
- Use `--detailed-output` to see full reasoning
- Check if code has complex data flows
- Consider manual review for low-confidence findings
- Try different LLM model (e.g., GPT-4o vs Gemini)

---

## Performance Tips

### Speed Optimization

1. **Use Ollama for Local Inference**: No network latency, unlimited requests
2. **Limit Findings**: Start with `--limit 10` for testing
3. **Filter by Severity**: Use `--severity high critical`
4. **Disable UI**: Skip `--ui` for faster processing
5. **Parallel Processing**: Split scans across multiple directories

### Cost Optimization

1. **Use Ollama**: Free, runs locally
2. **Filter Before Scanning**: Use Semgrep's `--severity` flag
3. **Cache Results**: Don't re-scan unchanged code
4. **Batch Scans**: Run weekly/monthly instead of per-commit
5. **Use Groq**: Fast and cost-effective commercial option

---

## Getting Help

- **Documentation**: Read the README.md for technical details
- **Examples**: Check `test_samples/` for sample vulnerable code
- **Issues**: Open GitHub issues for bugs or feature requests
- **Configuration**: See `.env.example` for all available settings

---

## Summary: When to Use AutoSAST

| Scenario | Frequency | Command |
|----------|-----------|---------|
| Developer pre-commit | Every commit | `python -m src.cli scan .` |
| CI/CD security gate | Every PR | `python -m src.cli scan . --severity high` |
| Security team review | Weekly | `python -m src.cli scan /app --detailed-output` |
| Compliance audit | Quarterly | `python -m src.cli scan /app -o audit.json` |
| Training session | As needed | `python -m src.cli scan ./examples --ui` |

---

**Ready to reduce false positives and focus on real security issues? Start scanning now!**

```bash
python -m src.cli scan .
```
