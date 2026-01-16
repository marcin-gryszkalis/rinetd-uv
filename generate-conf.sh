#!/usr/bin/env bash
# Extract example configuration from DOCUMENTATION.md and save to rinetd-uv.conf
# This ensures the example in documentation stays in sync with the distributed config file

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/DOCUMENTATION.md"
OUTPUT="$SCRIPT_DIR/rinetd-uv.conf"

# Check if source file exists
if [ ! -f "$SOURCE" ]; then
    echo "Error: Source file not found: $SOURCE"
    exit 1
fi

echo "Extracting example configuration from DOCUMENTATION.md..."

# Extract the example configuration block
# Strategy: Find "## EXAMPLE CONFIGURATION" section, then extract the first code block
awk '
    /^## EXAMPLE CONFIGURATION/ { in_section = 1; next }
    in_section && /^```$/ && !in_block { in_block = 1; next }
    in_section && /^```$/ && in_block { exit }
    in_section && in_block { print }
' "$SOURCE" > "$OUTPUT"

# Verify extraction succeeded (file should not be empty)
if [ ! -s "$OUTPUT" ]; then
    echo "Error: Failed to extract configuration - output file is empty"
    echo "Check that DOCUMENTATION.md contains '## EXAMPLE CONFIGURATION' section with a code block"
    exit 1
fi

# Count lines extracted
LINES=$(wc -l < "$OUTPUT")
echo "Example configuration extracted: $OUTPUT ($LINES lines)"
