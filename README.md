# OWASP Security Skills for Claude Code

> Bring the latest OWASP security standards directly into your Claude Code workflow — automatically, for every language and platform you work on.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-2025-red)](https://owasp.org/Top10/)
[![OWASP ASVS](https://img.shields.io/badge/OWASP%20ASVS-5.0.0-red)](https://github.com/OWASP/ASVS)
[![OWASP LLM](https://img.shields.io/badge/OWASP%20LLM%20Top%2010-2025-orange)](https://genai.owasp.org/)
[![OWASP Agentic](https://img.shields.io/badge/OWASP%20Agentic-2026-orange)](https://genai.owasp.org/)
[![OWASP API](https://img.shields.io/badge/OWASP%20API%20Security-2023-blue)](https://owasp.org/API-Security/)
[![OWASP Mobile](https://img.shields.io/badge/OWASP%20Mobile%20Top%2010-2024-blue)](https://owasp.org/www-project-mobile-top-10/)
[![OWASP CI/CD](https://img.shields.io/badge/OWASP%20CI%2FCD%20Security-Top%2010-green)](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

---

## What This Is

Five focused [Claude Code skills](https://docs.anthropic.com/en/docs/claude-code/skills) that activate automatically when you're doing relevant work — giving Claude the full context of current OWASP standards without you having to remember to ask.

Each skill is purpose-built and stays within Claude Code's compaction window (~5,000 tokens) so guidance survives long sessions.

| Skill | Standards | Activates When... |
|-------|-----------|-------------------|
| `owasp-web` | Top 10:2025, ASVS 5.0 | Reviewing web app code, auth, input handling, 20+ languages |
| `owasp-api` | API Security Top 10:2023 | Building REST/GraphQL APIs, SSRF prevention, JWT, rate limiting |
| `owasp-mobile` | Mobile Top 10:2024 | iOS/Android/React Native/Flutter development |
| `owasp-llm` | LLM Top 10:2025, Agentic:2026 | Building chatbots, RAG, agents, MCP servers, function calling |
| `owasp-cicd` | CI/CD Security Top 10 | GitHub Actions, Dockerfiles, IaC, dependency management |

---

## Quick Install

### Project-level (recommended for team use)

```bash
# All 5 skills
curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/install.sh | bash

# Or install individual skills:
curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/.claude/skills/owasp-web/SKILL.md \
  -o .claude/skills/owasp-web/SKILL.md --create-dirs

curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/.claude/skills/owasp-api/SKILL.md \
  -o .claude/skills/owasp-api/SKILL.md --create-dirs

curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/.claude/skills/owasp-llm/SKILL.md \
  -o .claude/skills/owasp-llm/SKILL.md --create-dirs

curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/.claude/skills/owasp-mobile/SKILL.md \
  -o .claude/skills/owasp-mobile/SKILL.md --create-dirs

curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/.claude/skills/owasp-cicd/SKILL.md \
  -o .claude/skills/owasp-cicd/SKILL.md --create-dirs
```

### Global install (all your projects)

```bash
curl -sL https://raw.githubusercontent.com/markusweldon/claude-owasp-security-skills/main/install.sh | bash -s -- --global
```

### Clone and install manually

```bash
git clone https://github.com/markusweldon/claude-owasp-security-skills.git
cd claude-owasp-security-skills
bash install.sh                    # project-level
bash install.sh --global           # global (~/.claude/skills/)
bash install.sh --skill owasp-llm  # single skill only
```

---

## What Each Skill Covers

### `owasp-web` — Web Application Security
- OWASP Top 10:2025 quick reference + prevention patterns
- Security code review checklist (input, auth, access control, data, errors)
- Secure vs unsafe code patterns for SQL injection, command injection, password storage, access control, fail-closed error handling
- ASVS 5.0 verification levels (L1/L2/L3)
- Language-specific security pitfalls for **JavaScript, Python, Java, C#, PHP, Go, Ruby, Rust, C/C++, Shell, SQL** (10 languages in skill; 10 more in `docs/`)
- Deep security analysis mindset checklist

### `owasp-api` — API Security
- OWASP API Security Top 10:2023 full coverage
- BOLA/IDOR prevention, mass assignment mitigation
- SSRF prevention with blocked internal IP ranges
- JWT security: algorithm pinning, claims validation, storage
- GraphQL-specific risks: depth limits, complexity, introspection
- Rate limiting patterns, API versioning & inventory checklist

### `owasp-mobile` — Mobile Security
- OWASP Mobile Top 10:2024 full coverage
- **iOS**: Keychain storage, ATS configuration, certificate pinning, jailbreak detection, screen masking
- **Android**: Keystore/EncryptedSharedPreferences, manifest hardening, SafetyNet/Play Integrity, ProGuard
- **Flutter/Dart**: flutter_secure_storage, secure communications
- **React Native**: AsyncStorage pitfalls, Hermes debugger, deep link validation
- Certificate pinning code for URLSession and OkHttp
- Privacy controls: PII in logs, background screen masking, permissions

### `owasp-llm` — LLM & AI Agent Security
- OWASP LLM Top 10:2025: prompt injection, output handling, excessive agency, system prompt leakage, vector store isolation, unbounded consumption
- OWASP Agentic AI 2026: goal hijacking, tool misuse, inter-agent communication, cascading failures, rogue agents
- Prompt injection defense patterns with structured roles
- Safe LLM output handling before SQL/shell/HTML/tool calls
- RAG/vector store tenant isolation
- PII scrubbing before LLM calls
- Sandboxed code execution for agent-generated code
- Agent authentication and kill switch patterns

### `owasp-cicd` — CI/CD & Supply Chain Security
- OWASP CI/CD Security Top 10 full coverage
- GitHub Actions hardening: SHA-pinned actions, minimal `permissions:` blocks, OIDC vs static secrets
- Docker security: pinned digests, non-root users, multi-stage builds
- Dependency pinning with hash verification (`npm ci`, `--require-hashes`)
- Artifact signing with Sigstore/cosign + SBOM generation
- Branch protection configuration reference
- Terraform/IaC security: `tfsec`/`checkov`, state file encryption, no secrets in `.tfvars`
- Webhook HMAC validation, third-party service governance

---

## Usage Examples

Once installed, skills activate automatically. You don't need to invoke them explicitly.

```
"Review this Express.js authentication middleware for security issues"
→ owasp-web activates

"Is this GraphQL resolver vulnerable to BOLA?"
→ owasp-api activates

"Check my GitHub Actions workflow for security problems"
→ owasp-cicd activates

"Is my RAG pipeline safe from prompt injection?"
→ owasp-llm activates

"Review this Swift Keychain implementation"
→ owasp-mobile activates
```

You can also invoke skills explicitly:

```
/owasp-web
/owasp-api
/owasp-mobile
/owasp-llm
/owasp-cicd
```

---

## Standards Coverage

| Standard | Version | Released |
|----------|---------|---------|
| OWASP Top 10 | 2025 | April 2025 |
| OWASP ASVS | 5.0.0 | May 2025 |
| OWASP Top 10 for LLM Applications | 2025 | 2025 |
| OWASP Top 10 for Agentic Applications | 2026 | December 2025 |
| OWASP API Security Top 10 | 2023 | 2023 |
| OWASP Mobile Top 10 | 2024 | 2024 |
| OWASP Top 10 CI/CD Security Risks | 2022 | 2022 |

---

## Design: Why 5 Skills Instead of 1?

Claude Code compresses skills under context pressure, retaining only the **first ~5,000 tokens** of each active skill. A single large SKILL.md would lose its tail during long sessions — exactly when security guidance matters most.

Five focused skills means:
- Each skill fits within the 5,000-token retention window
- Only relevant skills activate (mobile skill won't fire during backend work)
- Skills can be installed selectively — install just `owasp-llm` for an AI project
- Descriptions stay within the 1,536-character per-skill limit for accurate triggering

---

## Repository Structure

```
.claude/skills/
├── owasp-web/SKILL.md      # Web app security (Top 10:2025, ASVS 5.0)
├── owasp-api/SKILL.md      # API security (API Top 10:2023)
├── owasp-mobile/SKILL.md   # Mobile security (Mobile Top 10:2024)
├── owasp-llm/SKILL.md      # LLM + agentic AI security
└── owasp-cicd/SKILL.md     # CI/CD + supply chain security

docs/
└── language-security-reference.md  # Extended language quirks (10+ more languages)

install.sh                  # Installer script
```

---

## Contributing

Contributions welcome — especially:
- Updates when new OWASP standards are released
- Language-specific security patterns not yet covered
- Real-world vulnerable/safe code pattern additions
- Bug reports for incorrect guidance

See [CLAUDE.md](CLAUDE.md) for contributor guidelines and the development workflow.

**To contribute:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feat/owasp-api-graphql-patterns`
3. Make changes following the patterns in existing SKILL.md files
4. Submit a pull request using the PR template

---

## Sources

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/)
- [OWASP Mobile Top 10:2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NIST SP 800-63b](https://pages.nist.gov/800-63-3/)

---

## License

MIT — see [LICENSE](LICENSE).

---

*Inspired by [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp). Enhanced with API, Mobile, CI/CD coverage, multi-skill architecture, and 2024/2025/2026 standards updates.*
