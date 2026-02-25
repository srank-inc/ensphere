#!/bin/bash
# Install Ensphere security assessment skills for Claude Code

SKILL_DIR="$HOME/.claude/skills/ensphere"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Uninstall
if [ "$1" = "--uninstall" ]; then
  if [ -d "$SKILL_DIR" ]; then
    rm -rf "$SKILL_DIR"
    echo "Ensphere skills removed from $SKILL_DIR"
  else
    echo "Nothing to remove — $SKILL_DIR does not exist"
  fi
  exit 0
fi

# Verify source files exist
if [ ! -f "$SCRIPT_DIR/skills/SKILL.md" ]; then
  echo "Error: skills/SKILL.md not found. Run this script from the ensphere repo root." >&2
  exit 1
fi

echo "Installing Ensphere skills..."

# Create directories
mkdir -p "$SKILL_DIR/methodology" "$SKILL_DIR/shared" "$SKILL_DIR/checklists"

# Copy skill files
cp "$SCRIPT_DIR/skills/SKILL.md" "$SKILL_DIR/"
# Copy methodology if present
if ls "$SCRIPT_DIR/skills/methodology/"*.md 1>/dev/null 2>&1; then
  cp "$SCRIPT_DIR/skills/methodology/"*.md "$SKILL_DIR/methodology/"
fi

# Copy shared if present
if ls "$SCRIPT_DIR/skills/shared/"*.md 1>/dev/null 2>&1; then
  cp "$SCRIPT_DIR/skills/shared/"*.md "$SKILL_DIR/shared/"
fi

# Copy checklists if present
if ls "$SCRIPT_DIR/skills/checklists/"*.md 1>/dev/null 2>&1; then
  cp "$SCRIPT_DIR/skills/checklists/"*.md "$SKILL_DIR/checklists/"
fi

# Verify
file_count=$(find "$SKILL_DIR" -name "*.md" | wc -l | tr -d ' ')
echo "Ensphere skills installed to $SKILL_DIR ($file_count files)"
echo ""
echo "Files installed:"
find "$SKILL_DIR" -name "*.md" | sort | while read -r f; do
  echo "  $f"
done
echo ""
echo "Config template: templates/config.md (copy to your project's ensphere-pentest/config.md)"
echo "Usage: Open Claude Code in your project directory and say '/ensphere' or 'Run session 01'"
echo "Uninstall: $0 --uninstall"

# Optional: build CLI if Go is available
if command -v go &> /dev/null; then
  echo ""
  echo "Go detected — building ensphere CLI..."
  if (cd "$SCRIPT_DIR" && make build); then
    echo "CLI built at $SCRIPT_DIR/bin/ensphere"
    echo "Run 'make install' from the repo to install to /usr/local/bin"
  else
    echo "CLI build failed (non-fatal). Install Go 1.23+ and run 'make build' manually."
  fi
else
  echo ""
  echo "Go not found — skipping CLI build. Install Go 1.23+ and run 'make build' to build the payload database CLI."
fi
