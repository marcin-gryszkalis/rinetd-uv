#!/usr/bin/env bash
# Generate index.html from DOCUMENTATION.md

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/DOCUMENTATION.md"
OUTPUT="$SCRIPT_DIR/index.html"

# Check if pandoc is available
if ! command -v pandoc >/dev/null 2>&1; then
    echo "Error: pandoc is not installed"
    echo ""
    echo "Install pandoc:"
    echo "  Debian/Ubuntu: sudo apt-get install pandoc"
    echo "  Fedora/RHEL:   sudo dnf install pandoc"
    echo "  macOS:         brew install pandoc"
    echo "  Arch Linux:    sudo pacman -S pandoc"
    exit 1
fi

# Check if source file exists
if [ ! -f "$SOURCE" ]; then
    echo "Error: Source file not found: $SOURCE"
    exit 1
fi

echo "Generating HTML from DOCUMENTATION.md..."

# Generate HTML using pandoc
# -s = standalone document (includes <html>, <head>, <body> tags)
# -t html5 = output format is HTML5
# --metadata title="rinetd-uv - internet redirection server" = set page title
# --toc = generate table of contents
# --toc-depth=2 = include h1 and h2 in TOC
# -c = add CSS file (optional, can be customized)
pandoc -s -t html5 \
    --metadata title="rinetd-uv - internet redirection server" \
    --metadata date="$(date +%Y-%m-%d)" \
    --toc --toc-depth=2 \
    --css=style.css \
    "$SOURCE" -o "$OUTPUT"

echo "HTML documentation generated: $OUTPUT"
echo ""
echo "To view the generated HTML:"
echo "  firefox $OUTPUT"
echo "  # or"
echo "  google-chrome $OUTPUT"
echo "  # or"
echo "  xdg-open $OUTPUT"
