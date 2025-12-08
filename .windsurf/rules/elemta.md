---
trigger: always_on
---

# .cursorrules (or Windsurf project rules)
# Place this file at the repo root: /home/alan/repos/elemta/.cursorrules

version: 1

project:
  name: "elemta"
  language: "go"

# -----------------------------
# 1. File / directory priorities
# -----------------------------
priorities:
  # Core production code – AI can edit/suggest freely
  - paths:
      - "internal/smtp/**"
      - "internal/queue/**"
      - "internal/plugin/**"
      - "internal/api/**"
      - "internal/auth/**"
      - "internal/config/**"
      - "cmd/elemta/**"
      - "cmd/elemta-cli/**"
      - "cmd/elemta-queue/**"
    priority: high

  # Lower priority – only touch when explicitly asked
  - paths:
      - "examples/**"
      - "tests/scripts/**"
      - "deployments/**"
      - "k8s/**"
      - "elk/**"
      - "monitoring/**"
      - "docs/**"
    priority: low

# -----------------------------
# 2. Protected / manual-change files
# -----------------------------
protected_paths:
  # CI and security workflows – only change when requested
  - ".github/workflows/lint.yml"
  - ".github/workflows/security.yml"
  - ".github/workflows/build.yml"
  - ".github/workflows/deploy.yml"

  # Lint config is fragile, keep changes explicit
  - ".golangci.yml"

# -----------------------------
# 3. Ignore noisy / generated stuff
# -----------------------------
ignore:
  - "coverage.out"
  - "build/**"
  - "bin/**"
  - "venv/**"
  - "queue/**"          # runtime queue data
  - ".git/**"
  - ".cursor/**"

# -----------------------------
# 4. Commands / tooling conventions
# -----------------------------
commands:
  # Linting: always use make
  - name: "lint"
    description: "Run golangci-lint with project config"
    run: "make lint"

  # Auto-fix lint (if needed)
  - name: "lint-fix"
    description: "Run golangci-lint with --fix"
    run: "make lint-fix"

  # Tests
  - name: "test-all"
    description: "Run all Go tests"
    run: "go test ./..."

# -----------------------------
# 5. Refactor & framework rules
# -----------------------------
refactor_policy:
  # Prefer small, targeted diffs over large rewrites
  large_refactors: off

  # Do not introduce new web/HTTP frameworks unless explicitly requested
  preserve_frameworks: true

style:
  # Respect existing error-handling patterns and SMTP reply formats
  preserve_error_strings: true
  # Don’t auto-“fix” stylistic staticcheck warnings we’ve intentionally excluded
  avoid_style_only_changes: true