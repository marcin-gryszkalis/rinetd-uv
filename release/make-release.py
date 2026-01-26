#!/usr/bin/env python3
"""Generate release.sh from template with version-specific values baked in."""

import argparse
import os
import re
import stat
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(SCRIPT_DIR, "release.sh.template")
CHANGES_PATH = os.path.join(SCRIPT_DIR, "CHANGES.md")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "release.sh")


def parse_version(version_str):
    """Validate and parse MAJOR.MINOR.PATCH version string."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if not m:
        sys.exit(f"Error: '{version_str}' is not a valid MAJOR.MINOR.PATCH version")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def extract_release_notes(version):
    """Extract release notes section for the given version from CHANGES.md."""
    with open(CHANGES_PATH) as f:
        content = f.read()

    pattern = r"^## Version (\S+) \(([^)]+)\)"
    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        sys.exit("Error: no version section found in CHANGES.md")

    found_version = match.group(1)
    if found_version != version:
        sys.exit(f"Error: CHANGES.md top section is for version {found_version}, expected {version}")

    # Extract from this header until the next ## header or EOF
    rest = content[match.end():]
    next_section = re.search(r"^## ", rest, re.MULTILINE)
    if next_section:
        notes_body = rest[:next_section.start()]
    else:
        notes_body = rest

    # Return full section (header + body), stripped of trailing whitespace
    header = match.group(0)
    return (header + notes_body).rstrip()


def process_skip_sections(lines, skip_sections):
    """Comment out lines between @@BEGIN:section@@ and @@END:section@@ markers for skipped sections."""
    result = []
    skipping = None

    for line in lines:
        stripped = line.strip()

        # Check for begin marker
        begin_match = re.match(r"^#\s*@@BEGIN:(\w+)@@\s*$", stripped)
        if begin_match:
            section = begin_match.group(1)
            if section in skip_sections:
                skipping = section
                result.append(f"# [SKIPPED: {section}]\n")
            continue

        # Check for end marker
        end_match = re.match(r"^#\s*@@END:(\w+)@@\s*$", stripped)
        if end_match:
            section = end_match.group(1)
            if section == skipping:
                skipping = None
            continue

        # If inside a skipped section, comment it out
        if skipping:
            if stripped:
                result.append(f"# {line.rstrip()}\n")
            else:
                result.append("\n")
        else:
            result.append(line)

    return result


def render_template(version, release_notes, skip_sections):
    """Read template, substitute @@VAR@@ placeholders, handle skip sections."""
    major, minor, _ = parse_version(version)

    substitutions = {
        "VERSION": version,
        "VERSION_MAJOR": str(major),
        "VERSION_MINOR": f"{major}.{minor}",
        "TAG": f"v{version}",
        "RELEASE_NOTES": release_notes,
    }

    with open(TEMPLATE_PATH) as f:
        lines = f.readlines()

    # Process skip sections first
    lines = process_skip_sections(lines, skip_sections)

    # Join and substitute @@VAR@@ placeholders
    content = "".join(lines)
    for key, value in substitutions.items():
        content = content.replace(f"@@{key}@@", value)

    # Warn about any remaining @@...@@ placeholders (possible typos in template)
    remaining = re.findall(r"@@\w+@@", content)
    if remaining:
        print(f"Warning: unsubstituted placeholders in output: {', '.join(set(remaining))}", file=sys.stderr)

    return content


def main():
    parser = argparse.ArgumentParser(description="Generate release.sh from template")
    parser.add_argument("version", help="Release version (MAJOR.MINOR.PATCH)")
    parser.add_argument("--skip-tests", action="store_true", help="Skip test suite in generated script")
    parser.add_argument("--skip-docker", action="store_true", help="Skip Docker build/push in generated script")
    args = parser.parse_args()

    parse_version(args.version)

    release_notes = extract_release_notes(args.version)

    skip_sections = set()
    if args.skip_tests:
        skip_sections.add("tests")
    if args.skip_docker:
        skip_sections.add("docker")

    content = render_template(args.version, release_notes, skip_sections)

    with open(OUTPUT_PATH, "w") as f:
        f.write(content)

    # chmod +x
    st = os.stat(OUTPUT_PATH)
    os.chmod(OUTPUT_PATH, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Generated {OUTPUT_PATH} for version {args.version}")
    if skip_sections:
        print(f"Skipped sections: {', '.join(sorted(skip_sections))}")


if __name__ == "__main__":
    main()
