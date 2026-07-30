"""Auto-update the Supported Frameworks section in README.md from framework YAMLs.

Reads all framework YAML files and regenerates the "Supported frameworks"
bullet list in README.md between marker comments. Run this after adding or
removing a framework YAML.

Usage:
    python scripts/update_readme_frameworks.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "src" / "aws_india_compliance" / "frameworks"
README_PATH = REPO_ROOT / "README.md"

# Markers in README.md that bound the auto-generated section
START_MARKER = "<!-- FRAMEWORKS_START -->"
END_MARKER = "<!-- FRAMEWORKS_END -->"


def load_frameworks() -> list[dict]:
    """Load all framework YAMLs sorted by id."""
    frameworks: list[dict] = []
    for filepath in sorted(FRAMEWORKS_DIR.glob("*.yaml")):
        if filepath.name.startswith("_"):
            continue
        with open(filepath, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict) and "id" in data:
            frameworks.append(data)
    return frameworks


def generate_frameworks_section(frameworks: list[dict]) -> str:
    """Generate the bullet list of supported frameworks."""
    lines: list[str] = []
    for fw in frameworks:
        name = fw["name"]
        # Use a short display name: bold the short name, parenthetical description
        # Extract short name and description from the full name
        lines.append(f"- **{name}**")
    return "\n".join(lines)


def update_readme(frameworks: list[dict]) -> bool:
    """Update the README.md frameworks section between markers.

    Returns True if the file was modified, False if already up to date.
    """
    readme_text = README_PATH.read_text(encoding="utf-8")

    if START_MARKER not in readme_text or END_MARKER not in readme_text:
        print(
            f"Error: README.md does not contain the marker comments.\n"
            f"Add these lines where you want the frameworks list:\n"
            f"  {START_MARKER}\n"
            f"  {END_MARKER}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Split on markers
    before = readme_text.split(START_MARKER)[0]
    after = readme_text.split(END_MARKER)[1]

    # Generate new section
    section = generate_frameworks_section(frameworks)
    new_readme = f"{before}{START_MARKER}\n{section}\n{END_MARKER}{after}"

    if new_readme == readme_text:
        return False

    README_PATH.write_text(new_readme, encoding="utf-8")
    return True


def main() -> None:
    """Main entry point."""
    frameworks = load_frameworks()
    if not frameworks:
        print("Error: no framework YAML files found.", file=sys.stderr)
        sys.exit(1)

    modified = update_readme(frameworks)

    if modified:
        print(f"Updated README.md with {len(frameworks)} frameworks:")
        for fw in frameworks:
            print(f"  - {fw['name']}")
    else:
        print("README.md is already up to date.")


if __name__ == "__main__":
    main()
