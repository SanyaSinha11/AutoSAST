# AutoSAST Assets

This directory contains visual assets and demos for the AutoSAST project.

## Files

### 🎬 Demonstrations

#### **`cli_output.html`** ✨ NEW
Realistic HTML recreation of the actual AutoSAST CLI output featuring:
- **Authentic ASCII Banner** - Full AUTOSAST logo with cyan theme
- **Configuration Panel** - Shows all settings (LLM provider, Semgrep config, etc.)
- **Stage Panels** - Visual representation of the 3-stage scan process
- **Finding Results** - Color-coded individual finding boxes (red/green/yellow)
- **Summary Panel** - Statistics with ASCII progress bars
- **Performance Metrics** - Tree-style formatting showing timings and token usage
- **Dark Terminal Theme** - Matches actual CLI appearance (#0d1117 background)

**How to view:**
1. Open `cli_output.html` in any web browser
2. View locally: `open assets/cli_output.html` (macOS) or `xdg-open assets/cli_output.html` (Linux)
3. Or deploy to GitHub Pages / any web server

**Creating a GIF/Screenshot:**
- **macOS**: Cmd+Shift+4 → Drag to select → Creates screenshot
- **Screenshot tools**: [Kap](https://getkap.co/), [Gifox](https://gifox.io/), [LICEcap](https://www.cockos.com/licecap/)
- **Browser extensions**: Nimbus Screenshot, Awesome Screenshot
- **CLI**: `python3 scripts/generate_cli_gif.py` (requires pyppeteer & Pillow)

#### **`demo.html`** (Original)
Animated demonstration with JavaScript showing:
- Terminal window with macOS-style dots
- Typing animation for commands
- Progressive reveal of findings
- Summary statistics

**Color scheme:** Light theme with beige tones

### 🖼️ Images

#### **`logo.png`**
AutoSAST logo used in README.md and documentation.

---

## Creating Marketing Materials

### Option 1: Screenshot `cli_output.html`
```bash
# Open in browser
open assets/cli_output.html

# Take screenshot with your favorite tool
# Recommended size: 1280x1600 or similar
```

### Option 2: Use the Python Script (Advanced)
```bash
# Install dependencies
pip install pyppeteer Pillow

# Download Chromium (first time only)
pyppeteer-install

# Generate GIF
python3 scripts/generate_cli_gif.py
```

### Option 3: Use Online Tools
1. Open `assets/cli_output.html` in your browser
2. Use online screenshot tools:
   - [Screely](https://screely.com/) - Add browser frames
   - [Carbon](https://carbon.now.sh/) - Code screenshots
   - [Screenshot.rocks](https://screenshot.rocks/) - Mockups

---

## CLI Color Reference

For consistency across all materials, use these exact colors from the actual CLI:

| Element | Color Code | Usage |
|---------|------------|-------|
| **Primary (Cyan)** | `#00d9ff` | Banner, borders, labels |
| **Success (Green)** | `#00ff00` | Safe findings, success messages |
| **Warning (Yellow)** | `#ffff00` | Needs review, highlights |
| **Error (Red)** | `#ff0000` | Vulnerable findings |
| **Info (Magenta)** | `#ff00ff` | AI analysis stage |
| **Background** | `#0d1117` | Terminal background |
| **Text** | `#c9d1d9` | Default text |
| **Dim Text** | `#8b949e` | Secondary information |

---

## Stage Descriptions

For documentation, here's what each stage does:

**Stage 1: 🔍 Code Scanning**
- Runs Semgrep static analysis
- Finds potential vulnerabilities
- Uses configured security rules

**Stage 2: 🧠 AI Analysis**
- AI-powered triage using configured LLM
- Extracts code context and data flows
- Checks sanitization patterns
- Determines true vs. false positives

**Stage 3: 📊 Results**
- Aggregates all analysis results
- Saves JSON report to `results/` folder
- Displays color-coded findings
- Shows performance metrics

---

## Contributing

When adding new assets:
1. Keep file sizes reasonable (<5MB for images, <2MB for HTML)
2. Use optimized formats (WebP for images when possible)
3. Match the existing color scheme for consistency
4. Update this README with descriptions

---

**Last Updated:** 2026-06-12
