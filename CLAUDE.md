# Contributing to claude-owasp-security-skill

This repo contains Claude Code skills providing OWASP security guidance. There's no code to run or tests to pass — the "correctness" criterion is accuracy of security guidance and fit within Claude Code's skill constraints.

## Skill Architecture

Each skill is a standalone `SKILL.md` under `.claude/skills/<name>/`. They are designed to:
- Stay under **~300 lines** (~4,000 tokens) so the full content survives Claude Code's 5,000-token compaction window
- Have a `description:` + `when_to_use:` block under **1,536 characters total** (hard cap for skill listing)
- Activate automatically when Claude Code detects relevant work — no `/invoke` needed

```
.claude/skills/
├── owasp-web/SKILL.md      # OWASP Top 10:2025 + ASVS 5.0 + language quirks
├── owasp-api/SKILL.md      # OWASP API Security Top 10:2023
├── owasp-mobile/SKILL.md   # OWASP Mobile Top 10:2024
├── owasp-llm/SKILL.md      # OWASP LLM:2025 + Agentic:2026
└── owasp-cicd/SKILL.md     # OWASP CI/CD Security Top 10
```

Extended language reference lives in `docs/language-security-reference.md` (not a skill — Claude reads it on demand when doing deep language-specific reviews).

## Making Changes

### Updating a skill for a new OWASP release
1. Check the official source (links in README Sources section) for what changed
2. Update the quick-reference table first, then code patterns, then checklists
3. Remove outdated patterns — do not just append; the line budget matters
4. Update the badge version in README.md

### Adding a new language to `owasp-web`
- The in-skill section (owasp-web/SKILL.md) should be **≤10 lines per language**: one unsafe/safe snippet + a Watch-for list
- Full deep-dive goes in `docs/language-security-reference.md`
- Add a note at the bottom of the owasp-web language section referencing the docs file

### Adding a new skill
Create `.claude/skills/<name>/SKILL.md` with this frontmatter:
```yaml
---
name: <kebab-case>
description: <one-sentence: what standard, what it covers — ≤200 chars>
when_to_use: <trigger phrases and contexts — combined with description must be ≤1536 chars>
---
```

### Code pattern guidelines
- Every pattern must have an explicit `# UNSAFE` and `# SAFE` label
- Use Python for generic examples (most readable); use the native language for language-specific sections
- Patterns should be minimal — illustrate the exact vulnerability, not a full application
- Do not use placeholder company names or fake domains in patterns

## Validation Checklist

Before submitting a PR, verify:
- [ ] `description` + `when_to_use` combined length is ≤ 1,536 characters (`wc -c`)
- [ ] Skill file is ≤ 350 lines (`wc -l`)
- [ ] All code patterns have `# UNSAFE` / `# SAFE` labels
- [ ] Security guidance is sourced from official OWASP materials (link in PR if new content)
- [ ] README badges and standards table updated if version changed
- [ ] `install.sh` SKILLS array updated if new skill added

## What Belongs Where

| Content | Location |
|---------|----------|
| Quick-reference table + checklist + 2-3 code patterns | `SKILL.md` |
| Deep per-language analysis (10+ languages) | `docs/language-security-reference.md` |
| Full narrative explanation of each OWASP risk | `docs/OWASP-2025-2026-Report.md` |
| Install automation | `install.sh` |

## Reporting Incorrect Guidance

If you find security guidance that is wrong or outdated, open an issue using the **Security Guidance Error** template. Include:
- Which skill and section
- What the current guidance says
- What the correct guidance is
- Source (OWASP page, CVE, etc.)
