## What does this change?

<!-- Which skill(s) and what was updated -->

## Why?

<!-- New standard release, incorrect guidance, missing coverage, etc. Link to source -->

## Checklist

- [ ] `description` + `when_to_use` ≤ 1,536 characters (run: `awk '/^---/{p++} p==2{exit} p==1{print}' SKILL.md | wc -c`)
- [ ] Skill file ≤ 350 lines (`wc -l .claude/skills/*/SKILL.md`)
- [ ] All new code patterns have `# UNSAFE` / `# SAFE` labels
- [ ] Security guidance sourced from official OWASP materials
- [ ] README badges/table updated if a standard version changed
- [ ] `install.sh` SKILLS array updated if a new skill was added

## Source

<!-- Link to OWASP page, CVE, or other authoritative reference for new/changed content -->
