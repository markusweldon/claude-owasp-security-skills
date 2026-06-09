---
name: owasp-cicd
description: Apply OWASP CI/CD Security Top 10 standards when reviewing or building build pipelines, GitHub Actions workflows, deployment scripts, Dockerfiles, infrastructure-as-code, or dependency management. Covers poisoned pipeline execution, insufficient credential hygiene, artifact integrity, and supply chain abuse.
when_to_use: Use when working with GitHub Actions, GitLab CI, Jenkins, CircleCI, or any CI/CD pipeline. Also use for Dockerfile security, Terraform/IaC hardening, secrets management in pipelines, dependency pinning, SBOM generation, container image scanning, or software supply chain security.
---

# OWASP CI/CD Security Top 10

## Quick Reference

| # | Risk | Key Mitigation |
|---|------|----------------|
| CICD-SEC-1 | Insufficient Flow Control | Branch protection, required reviews, merge checks |
| CICD-SEC-2 | Inadequate IAM | Least-privilege tokens, OIDC over static secrets |
| CICD-SEC-3 | Dependency Chain Abuse | Pin versions with hashes, audit lockfiles, use private registries |
| CICD-SEC-4 | Poisoned Pipeline Execution | Restrict PR triggers, pin actions to commit SHA, review IaC changes |
| CICD-SEC-5 | Insufficient PBAC | Limit pipeline permissions, separate build from deploy |
| CICD-SEC-6 | Insufficient Credential Hygiene | No hardcoded secrets, rotate regularly, scope to minimum |
| CICD-SEC-7 | Insecure System Configuration | Harden runners, no debug in prod, isolated environments |
| CICD-SEC-8 | Ungoverned 3rd-Party Services | Audit external integrations, webhook validation, service allowlists |
| CICD-SEC-9 | Improper Artifact Integrity | Sign artifacts, verify signatures, SBOMs, provenance attestation |
| CICD-SEC-10 | Insufficient Logging | Audit all pipeline actions, alert on anomalies, immutable logs |

---

## CI/CD Security Checklist

### GitHub Actions Hardening (CICD-SEC-4, CICD-SEC-5)
```yaml
# UNSAFE — mutable action tag, overbroad permissions
jobs:
  build:
    permissions: write-all
    steps:
      - uses: actions/checkout@v4         # mutable tag
      - uses: some-org/unknown-action@v1  # unverified action

# SAFE — pinned to commit SHA, minimal permissions
jobs:
  build:
    permissions:
      contents: read       # only what's needed
      packages: write      # only if publishing
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af  # v4.1.0
```

**Checklist:**
- [ ] All `uses:` pinned to full commit SHA (not tag or branch)
- [ ] `permissions:` block on every job — start from `{}` and add only what's needed
- [ ] `pull_request_target` trigger avoided or tightly restricted (enables fork code to access secrets)
- [ ] `GITHUB_TOKEN` permissions set at workflow level with job-level overrides
- [ ] Third-party actions reviewed before use; prefer actions from `actions/` or `github/` orgs

### Secrets Management (CICD-SEC-6)
```yaml
# UNSAFE — hardcoded secret
env:
  API_KEY: "sk-prod-abc123xyz"

# SAFE — use GitHub Secrets, never hardcode
env:
  API_KEY: ${{ secrets.API_KEY }}
```

```yaml
# BEST PRACTICE — OIDC instead of static credentials (CICD-SEC-2)
jobs:
  deploy:
    permissions:
      id-token: write  # required for OIDC
      contents: read
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@xxxxxxxx
        with:
          role-to-assume: arn:aws:iam::123456789:role/deploy-role
          aws-region: us-east-1
          # No static AWS_ACCESS_KEY_ID needed — OIDC generates short-lived token
```

**Checklist:**
- [ ] No secrets in workflow YAML, Dockerfiles, or IaC files
- [ ] Use OIDC federation instead of long-lived static credentials where possible
- [ ] Secrets scoped to the minimum required — per-environment, not org-wide
- [ ] Secret rotation schedule enforced
- [ ] `git-secrets` or `truffleHog` / `gitleaks` run in pre-commit and CI

### Dependency Pinning (CICD-SEC-3)
```json
// package.json — UNSAFE: range versions
{
  "dependencies": {
    "express": "^4.18.0",  // vulnerable version could be resolved
    "lodash": "*"           // any version
  }
}

// SAFE: exact versions + lockfile integrity
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
```

```bash
# Verify lockfile integrity in CI
npm ci                    # uses package-lock.json exactly, fails if not matching
npm audit --audit-level=high  # fail on high/critical CVEs

# Python
pip install --require-hashes -r requirements.txt  # all packages must have hashes

# Gradle (build.gradle)
configurations.all {
    resolutionStrategy.failOnVersionConflict()
}
```

**Checklist:**
- [ ] Lockfiles committed to repository and verified in CI (`npm ci`, not `npm install`)
- [ ] Dependency hash verification enabled
- [ ] Automated dependency updates with auto-merging of low-risk patch bumps (Dependabot/Renovate)
- [ ] Private package registry configured to prevent dependency confusion attacks
- [ ] `npm audit`, `pip-audit`, `gradle dependencyCheckAnalyze`, or Snyk run in CI

### Docker & Container Security (CICD-SEC-7, CICD-SEC-9)
```dockerfile
# UNSAFE
FROM ubuntu:latest          # mutable, no integrity guarantee
RUN apt-get install -y curl | bash  # pipe to bash from internet
USER root                   # running as root

# SAFE
FROM ubuntu:22.04@sha256:a6d2b38300ce017add71440577d5b0a90460d0e57fd7aec21dd0d1aa7313427  # pinned digest
RUN apt-get update && apt-get install -y --no-install-recommends curl=7.81.0-1ubuntu1.16 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 1001 appuser
USER 1001                   # non-root user
```

**Dockerfile checklist:**
- [ ] Base image pinned to digest (not just tag)
- [ ] No `curl | bash` or similar remote script execution at build time
- [ ] Runs as non-root user
- [ ] No secrets in `ENV`, `ARG`, or `COPY` commands
- [ ] Multi-stage build to exclude build tools from final image
- [ ] Container image scanned with Trivy, Grype, or Snyk in CI before push

### Artifact Integrity & Provenance (CICD-SEC-9)
```yaml
# Generate SBOM and sign artifacts with Sigstore
- name: Generate SBOM
  uses: anchore/sbom-action@xxxxxxxx
  with:
    image: myorg/myapp:${{ github.sha }}

- name: Sign image with cosign
  run: |
    cosign sign --yes \
      -a "repo=${{ github.repository }}" \
      -a "workflow=${{ github.workflow }}" \
      myorg/myapp@${{ steps.build.outputs.digest }}

# Verify signature before deployment
- name: Verify image signature
  run: |
    cosign verify \
      --certificate-identity "https://github.com/${{ github.repository }}/.github/workflows/build.yml@refs/heads/main" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      myorg/myapp:latest
```

### Branch Protection & Flow Control (CICD-SEC-1)
```
GitHub Branch Protection Settings for main/master:
✓ Require pull request reviews before merging (≥1 reviewer)
✓ Require status checks to pass (tests, security scan, lint)
✓ Require branches to be up to date before merging
✓ Require signed commits
✓ Do not allow bypassing the above settings (including admins)
✓ Restrict force pushes
✓ Restrict deletions
```

### Pipeline Permissions (CICD-SEC-5)
```yaml
# Principle of least privilege per job
jobs:
  test:
    permissions:
      contents: read      # read source only
  
  build:
    permissions:
      contents: read
      packages: write     # push to GHCR
  
  deploy:
    permissions:
      id-token: write     # OIDC token for cloud auth
      deployments: write  # update deployment status
    environment: production  # require environment approval gate
```

### Third-Party Service Governance (CICD-SEC-8)
- [ ] All webhooks use shared secrets and verify HMAC signatures
- [ ] Outbound connections from CI runners limited to known hosts
- [ ] Third-party CI/CD integrations audited quarterly
- [ ] Slack/PagerDuty/JIRA integrations use bot tokens with minimal scopes
- [ ] External status checks from known, authenticated sources only

### Pipeline Logging & Alerting (CICD-SEC-10)
- [ ] All pipeline runs logged with actor, trigger, ref, and outcome
- [ ] Secret access attempts logged (GitHub audit log, CloudTrail, etc.)
- [ ] Alert on: failed signature verification, new external action introduced, permission escalation
- [ ] Logs shipped to SIEM — not stored only in CI provider (vendor lock/deletion risk)

---

## IaC Security (Terraform / Helm / K8s)

```hcl
# Terraform — UNSAFE
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # no encryption, no versioning, no public access block
}

# SAFE
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
```

**IaC checklist:**
- [ ] `tfsec` / `checkov` / `kube-score` run in CI on every PR
- [ ] State files stored with encryption and access logging
- [ ] Workspaces isolated per environment (no prod state in dev pipeline)
- [ ] No sensitive values in `.tfvars` files committed to repo — use Vault or cloud secret managers
