#!/bin/bash
# Generate rinetd.8 man page from DOCUMENTATION.md

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/DOCUMENTATION.md"
OUTPUT="$SCRIPT_DIR/rinetd.8"

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

echo "Generating man page from DOCUMENTATION.md..."

# Generate man page using pandoc
# -s = standalone document
# -t man = output format is man page
# --metadata title="rinetd" = set title
# --metadata section="8" = man section 8 (system administration)
# --metadata date="$(date +%Y-%m-%d)" = set current date
pandoc -s -t man \
    --metadata title="rinetd" \
    --metadata section="8" \
    --metadata date="$(date +%Y-%m-%d)" \
    --metadata footer="rinetd 0.73" \
    "$SOURCE" -o "$OUTPUT"

echo "Man page generated: $OUTPUT"
echo ""
echo "To view the generated man page:"
echo "  man ./$OUTPUT"
echo ""
echo "To install the man page:"
echo "  sudo cp $OUTPUT /usr/local/share/man/man8/"
echo "  sudo mandb  # Update man page database"
