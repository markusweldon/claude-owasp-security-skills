#!/usr/bin/env bash
# install.sh — install OWASP security skills for Claude Code
set -euo pipefail

REPO="markusweldon/claude-owasp-security-skill"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
SKILLS=(owasp-web owasp-api owasp-mobile owasp-llm owasp-cicd)

GLOBAL=false
SINGLE_SKILL=""

usage() {
  echo "Usage: $0 [--global] [--skill <name>]"
  echo ""
  echo "Options:"
  echo "  --global          Install to ~/.claude/skills/ (all projects)"
  echo "  --skill <name>    Install only one skill (e.g. owasp-llm)"
  echo ""
  echo "Available skills: ${SKILLS[*]}"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --global) GLOBAL=true; shift ;;
    --skill)  SINGLE_SKILL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -n "$SINGLE_SKILL" ]]; then
  VALID=false
  for s in "${SKILLS[@]}"; do [[ "$s" == "$SINGLE_SKILL" ]] && VALID=true; done
  if [[ "$VALID" == false ]]; then
    echo "Error: unknown skill '$SINGLE_SKILL'. Valid: ${SKILLS[*]}"
    exit 1
  fi
  SKILLS=("$SINGLE_SKILL")
fi

if $GLOBAL; then
  DEST="$HOME/.claude/skills"
  echo "Installing ${SKILLS[*]} globally to $DEST"
else
  DEST=".claude/skills"
  echo "Installing ${SKILLS[*]} to $DEST (project-level)"
fi

for skill in "${SKILLS[@]}"; do
  target_dir="${DEST}/${skill}"
  mkdir -p "$target_dir"
  echo "  Downloading ${skill}/SKILL.md..."
  curl -fsSL "${RAW_BASE}/.claude/skills/${skill}/SKILL.md" -o "${target_dir}/SKILL.md"
  echo "  ✓ ${skill}"
done

echo ""
echo "Done! Skills installed:"
for skill in "${SKILLS[@]}"; do
  echo "  • /$(basename "$DEST")/${skill}/SKILL.md"
done
echo ""
echo "Skills activate automatically in Claude Code. You can also invoke them with:"
for skill in "${SKILLS[@]}"; do
  echo "  /${skill}"
done
