#!/usr/bin/env bash
# Extract example configurations from DOCUMENTATION.md and save to config files
# This ensures the examples in documentation stay in sync with the distributed config files

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/DOCUMENTATION.md"
OUTPUT_LEGACY="$SCRIPT_DIR/rinetd-uv.conf"
OUTPUT_YAML="$SCRIPT_DIR/rinetd-uv.yaml"

# Check if source file exists
if [ ! -f "$SOURCE" ]; then
    echo "Error: Source file not found: $SOURCE"
    exit 1
fi

echo "Extracting example configurations from DOCUMENTATION.md..."

# Extract the legacy format configuration block
# Strategy: Find "### Legacy Format" section, then extract the code block
awk '
    /^### Legacy Format/ { in_section = 1; next }
    /^### / && in_section && !/^### Legacy Format/ { exit }
    /^## / && in_section { exit }
    in_section && /^```$/ && !in_block { in_block = 1; next }
    in_section && /^```$/ && in_block { exit }
    in_section && in_block { print }
' "$SOURCE" > "$OUTPUT_LEGACY"

# Extract the YAML format configuration block
# Strategy: Find "### YAML Format" section, then extract the code block
awk '
    /^### YAML Format/ { in_section = 1; next }
    /^### / && in_section && !/^### YAML Format/ { exit }
    /^## / && in_section { exit }
    in_section && /^```(yaml)?$/ && !in_block { in_block = 1; next }
    in_section && /^```$/ && in_block { exit }
    in_section && in_block { print }
' "$SOURCE" > "$OUTPUT_YAML"

# Verify legacy extraction succeeded (file should not be empty)
if [ ! -s "$OUTPUT_LEGACY" ]; then
    echo "Error: Failed to extract legacy configuration - output file is empty"
    echo "Check that DOCUMENTATION.md contains '### Legacy Format' section with a code block"
    exit 1
fi

# Verify YAML extraction succeeded (file should not be empty)
if [ ! -s "$OUTPUT_YAML" ]; then
    echo "Error: Failed to extract YAML configuration - output file is empty"
    echo "Check that DOCUMENTATION.md contains '### YAML Format' section with a code block"
    exit 1
fi

# Count lines extracted
LINES_LEGACY=$(wc -l < "$OUTPUT_LEGACY")
LINES_YAML=$(wc -l < "$OUTPUT_YAML")
echo "Legacy configuration extracted: $OUTPUT_LEGACY ($LINES_LEGACY lines)"
echo "YAML configuration extracted: $OUTPUT_YAML ($LINES_YAML lines)"
