# Elemta Development Tasks

**Last Updated:** 2026-02-04
**Branch:** `develop`
**Status:** Active development tracking

---

## 🔥 Critical Issues (Fix First)

### 1. Relay Permission Logic Broken
**Priority:** HIGH
**Files:** `internal/smtp/session_commands.go`
**Status:** 🔴 Blocking 10 tests

**Problem:**
- `isLocalDomain()` function not working correctly
- Local domains are being rejected with "554 5.7.1 Relay access denied"
- Affects both integration and functional tests

**Failing Tests:**
- `TestIntegration_BasicSMTPFlow` (and 7 other integration tests)
- `TestSMTP_DomainHandling/Local_Domain_Accepted`
- `TestSMTP_DomainHandling/External_Domain_Relay_Denied`

**Investigation Needed:**
```bash
# Test locally (currently skipped in short mode):
go test ./tests/integration -run TestIntegration_BasicSMTPFlow -v
go test ./tests -run TestSMTP_DomainHandling -v
```

**Diagnosis Steps:**
1. Add debug logging to `isLocalDomain()` function (line 899)
2. Verify `config.LocalDomains` is being passed correctly to CommandHandler
3. Check if recipient email parsing is working (@ split)
4. Test with simple direct connection to SMTP server

**Expected Fix Location:**
- `internal/smtp/session_commands.go:899-917` - `isLocalDomain()` function
- `internal/smtp/session.go:127-128` - Config passing to CommandHandler

---

## 🧪 Testing Improvements

### 2. Re-enable Skipped Tests (After Relay Fix)
**Priority:** MEDIUM
**Status:** ⏸️ Waiting on relay permission fix

**Currently Skipped (10 tests):**
```bash
# Integration tests (8 tests in tests/integration/smtp_flow_test.go)
- TestIntegration_BasicSMTPFlow
- TestIntegration_ConcurrentConnections
- TestIntegration_AuthenticationFlow
- TestIntegration_TLSFlow
- TestIntegration_ErrorRecovery
- TestIntegration_LargeMessages
- TestIntegration_PersistentConnection
- TestIntegration_TimeoutHandling

# Functional tests (2 tests in tests/smtp_functional_test.go)
- TestSMTP_ErrorHandling
- TestSMTP_DomainHandling
```

**Action Items:**
1. Fix relay permission logic (#1 above)
2. Remove `testing.Short()` skip conditions
3. Verify all tests pass without `-short` flag
4. Update test documentation

### 3. Add Integration Test Infrastructure
**Priority:** LOW
**Files:** `tests/integration/`

**Missing Setup:**
- TLS certificates for integration tests (`/tmp/test-cert.pem`)
- LDAP test datasource configuration
- Mock authentication service

**Improvements Needed:**
- Auto-generate test certificates in `setupIntegrationServer()`
- Mock LDAP datasource for auth tests
- Reduce test flakiness with retry logic

---

## 📝 Code Quality & Cleanup

### 4. Implement TODOs in Codebase
**Priority:** MEDIUM
**Status:** 📋 Cataloged, needs prioritization

**High Priority TODOs:**
```go
// internal/queue/interfaces.go:16
TODO: Implement database storage backend

// internal/plugin/sandbox.go:252
TODO: Implement CPU monitoring for plugins

// internal/api/server.go:450
TODO: Implement actual config updates

// internal/api/server.go:523
TODO: Implement graceful restart mechanism

// internal/api/middleware.go:87
TODO: Implement actual rate limiting
```

**Medium Priority TODOs:**
```go
// internal/plugin/hotreload.go:139
TODO: Implement graceful shutdown for hot reload

// internal/plugin/security_config.go:88-89
TODO: Implement actual TOML/JSON/YAML loading/saving

// internal/api/health_handler.go:304
TODO: Implement metrics tracking for health counters

// internal/cluster/cluster.go:171
TODO: Get version from version package (not hardcoded)
```

**Action:** Review each TODO, create specific issues, prioritize

### 5. Reduce Cyclomatic Complexity
**Priority:** LOW
**Files:** Various (6 functions flagged)

**Functions Exceeding Complexity Limit (>30):**
1. `NewServer()` - 45 (internal/smtp/server.go:48)
2. `LMTPDeliveryHandler.DeliverMessageWithMetadata()` - 44 (internal/queue/lmtp_handler.go:52)
3. `Router.ruleMatches()` - 38 (internal/delivery/router.go:220)
4. `startServer()` - 34 (cmd/elemta/commands/server.go:50)
5. `Server.Close()` - 33 (internal/smtp/server.go:768)
6. `tailLogFile()` - 31 (internal/api/server.go:1038)

**Refactoring Strategy:**
- Extract validation logic into separate functions
- Break down large switch/if-else chains
- Use strategy pattern for complex routing rules

### 6. Security Improvements (gosec Warnings)
**Priority:** MEDIUM-HIGH
**Category:** Security hardening

**Crypto Issues (HIGH):**
```bash
# Weak cryptographic primitives (SHA1/MD5)
- internal/auth/auth.go:12,220,250,276 - SHA1 usage
- internal/smtp/session_data.go:8 - MD5 import

Action: Replace with SHA256 or bcrypt for password hashing
```

**TLS Issues (MEDIUM):**
```bash
# Missing security settings
- internal/smtp/metrics.go:222 - Missing ReadHeaderTimeout
- internal/smtp/tls.go:446 - Missing ReadHeaderTimeout
- internal/smtp/tls_security.go:93 - TLS MinVersion too low

Action: Set ReadHeaderTimeout (10s), MinVersion to TLS 1.2
```

**File Permissions (MEDIUM):**
```bash
# Files created with 0644 (should be 0600)
- internal/message/message.go:62,92 - Message files too permissive

Action: Change to 0600 for security-sensitive files
```

**SQL Injection Risk (LOW - using parameterized queries):**
```bash
# SQL string formatting (false positive - table names)
- internal/datasource/mysql.go:309,536,614

Action: Document that table names are from config, not user input
```

---

## 🚀 Feature Development

### 7. Complete Feature Branches
**Priority:** VARIES
**Status:** 🌿 Multiple branches in progress

**Active Feature Branches:**
```bash
feature/allowdeny-plugin-for-access-control-ELE-42
fix/config-validation-crash-ELE-32
fix/dependency-security-vulnerabilities-ELE-34
fix/dockerfile-security-hardening-ELE-5
fix/memory-exhaustion-protection-ELE-16
fix/smtp-command-parsing-buffer-overflow-ELE-33
fix/tls-certificate-validation-ELE-22
fix/tls-security-hardening-ELE-9
fix/worker-pool-resource-management-ELE-35
```

**Action Items:**
1. Review each branch status
2. Merge completed work to `develop`
3. Close stale branches
4. Update JIRA/issue tracker

### 8. Database Queue Backend
**Priority:** MEDIUM
**Files:** `internal/queue/interfaces.go`

**Current State:**
- File-based queue only (works but not scalable)
- TODO placeholder for database backend

**Requirements:**
- PostgreSQL/MySQL backend option
- Message persistence in database
- Queue operations (enqueue, dequeue, requeue)
- Migration from file-based to DB-based

**Design:**
- Interface already defined: `QueueBackend`
- Need implementation: `DatabaseQueueBackend`
- Config option: `queue_backend: "database"` vs `"file"`

### 9. Plugin Hot Reload
**Priority:** LOW
**Files:** `internal/plugin/hotreload.go`

**Missing:**
- Graceful shutdown of old plugin instances (TODO line 139)
- Safe state transition during reload
- Rollback mechanism if new plugin fails

**Implementation Steps:**
1. Add plugin versioning
2. Implement graceful drain of in-flight requests
3. Add health checks before cutover
4. Rollback on failure

---

## 📚 Documentation

### 10. Update Documentation for Recent Changes
**Priority:** LOW
**Files:** `docs/`, `README.md`, `CLAUDE.md`

**Outdated Sections:**
- RFC 5321 compliance status (now 100% passing)
- Test infrastructure changes (skipped tests)
- New linter configuration
- Relay permission configuration

**Action:**
- Update PROGRESS.md with latest status
- Add troubleshooting section for relay issues
- Document test skip conditions

### 11. API Documentation Gaps
**Priority:** LOW
**Files:** `docs/api-reference.md`

**Missing Endpoints:**
- `/api/v1/config` endpoints (TODO in server.go)
- `/api/v1/reload` graceful restart
- Health check details
- Rate limiting configuration

---

## 🔧 Technical Debt

### 12. Unused Parameters (unparam findings)
**Priority:** LOW
**Status:** 🧹 Code cleanup

**Pattern:** Many interface implementations have unused `ctx context.Context`

**Examples:**
```go
internal/smtp/session_commands.go:655 - validateDomainName(ctx, domain)
internal/smtp/session_commands.go:812 - parseRcptTo(ctx, args)
internal/smtp/session_commands.go:899 - isLocalDomain(ctx, recipient)
```

**Options:**
1. Keep for consistency (interfaces may need ctx in future)
2. Remove if truly never used
3. Use for context-aware logging

**Recommendation:** Keep `ctx` parameters for consistency and future-proofing

### 13. Line Length Violations (lll)
**Priority:** LOW
**Files:** Multiple (plugin/, internal/plugin/)

**Issue:** 50+ lines exceeding 120 character limit

**Strategy:**
- Extract long struct tags to separate lines
- Break long function signatures
- Use shorter variable names where appropriate
- Add line breaks in function chains

**Example Fix:**
```go
// Before (177 chars)
func (p *MyDMARCPlugin) EvaluateDMARC(fromDomain string, spfResult plugin.SPFResult, spfDomain string, dkimResults []*plugin.DKIMVerifyResult) (*plugin.DMARCEvaluation, error) {

// After
func (p *MyDMARCPlugin) EvaluateDMARC(
    fromDomain string,
    spfResult plugin.SPFResult,
    spfDomain string,
    dkimResults []*plugin.DKIMVerifyResult,
) (*plugin.DMARCEvaluation, error) {
```

---

## 🎯 Performance Optimization

### 14. Memory Profiling & Optimization
**Priority:** LOW
**Files:** `internal/performance/memory_optimizer.go`

**Current Gaps:**
- Integer overflow warnings (G115) in memory stats conversion
- LastGC time conversion uint64 -> int64

**Improvements:**
- Add overflow checks
- Use safe type conversions
- Profile memory usage under load

### 15. Connection Pool Enhancements
**Priority:** MEDIUM
**Files:** `internal/smtp/connection_pool.go`

**Current Issues:**
- Validator not always called (fixed in recent commits)
- Statistics tracking (fixed in recent commits)

**Future Enhancements:**
- Connection health checks
- Automatic pool sizing based on load
- Metrics for pool efficiency

---

## 📊 Monitoring & Observability

### 16. Enhanced Metrics Collection
**Priority:** MEDIUM
**Files:** `internal/metrics/`, `internal/api/health_handler.go`

**Missing Metrics:**
- Relay permission denials (track why emails rejected)
- Queue processing latency percentiles
- Plugin execution times
- TLS handshake failures

**Action:**
- Add Prometheus metrics for relay decisions
- Track plugin performance
- Add RED metrics (Rate, Errors, Duration)

### 17. Structured Logging Improvements
**Priority:** LOW
**Files:** Various

**Enhancements Needed:**
- Consistent log levels across components
- Request tracing with correlation IDs
- Sensitive data redaction
- Log sampling for high-volume events

---

## 🔐 Security Enhancements

### 18. Replace Weak Cryptography
**Priority:** HIGH
**Files:** `internal/auth/auth.go`, `internal/smtp/session_data.go`

**Current State:**
- SHA1 used for password hashing (auth.go:220,250,276)
- MD5 imported (session_data.go:8)

**Action Plan:**
1. Audit all crypto usage
2. Replace SHA1 passwords with bcrypt
3. Remove MD5 import (check if actually used)
4. Add crypto usage documentation

### 19. TLS Security Hardening
**Priority:** MEDIUM
**Files:** `internal/smtp/tls_security.go`, `internal/smtp/tls.go`

**Required Changes:**
```go
// Add to HTTP servers
&http.Server{
    ReadHeaderTimeout: 10 * time.Second,  // Prevent Slowloris
    // ... other settings
}

// Update TLS config
&tls.Config{
    MinVersion: tls.VersionTLS12,  // Not TLS 1.0
    // ... other settings
}
```

### 20. Dependency Security Updates
**Priority:** MEDIUM
**Status:** 🔄 Ongoing (Dependabot active)

**Active Dependabot Branches:**
- `dependabot/docker/alpine-3.22`
- `dependabot/docker/alpine-3.23`
- `dependabot/docker/golang-1.25-alpine`
- `dependabot/github_actions/*` (multiple)
- `dependabot/go_modules/*` (multiple)

**Action:**
- Review and merge Dependabot PRs
- Test for breaking changes
- Update go.mod dependencies

---

## 🎓 Learning & Research

### 21. RFC 5321 Compliance Review
**Priority:** LOW
**Status:** ✅ Tests passing, but can always improve

**Current Status:**
- All RFC 5321 test suites passing (16/16)
- Case-insensitive command parsing fixed
- Special character support added

**Future Work:**
- Review other RFCs (5322, 6376, 7208, 7489)
- Add RFC 2821 compatibility mode
- SMTP pipelining optimization

### 22. Kubernetes Production Readiness
**Priority:** MEDIUM
**Files:** `k8s/`, `deployments/`

**Improvements Needed:**
- Horizontal Pod Autoscaling (HPA) configuration
- Pod Disruption Budgets (PDB)
- Network policies
- Service mesh integration (Istio/Linkerd)
- Persistent volume claims for queue

---

## ✅ Recently Completed

### ✓ Test Infrastructure Fixes
- Fixed all 26 SMTP unit test failures (2026-02-04)
- Implemented random port allocation for tests
- Fixed worker pool shutdown handling
- Fixed connection pool validator and statistics

### ✓ Linter Configuration
- Reduced linter errors from 100+ to ~10 actionable items (2026-02-04)
- Added practical exclude rules
- Configured for golangci-lint 1.64.5 compatibility

### ✓ RFC 5321 Compliance
- All 16 RFC 5321 test suites passing (2026-02-04)
- Case-insensitive command parsing
- Special character support in email addresses
- Parameter length limits enforced

---

## 📅 Suggested Priority Order

### Sprint 1 (This Week)
1. **Fix relay permission logic** (#1) - CRITICAL
2. **Re-enable skipped tests** (#2) - Dependent on #1
3. **Replace weak cryptography** (#18) - Security

### Sprint 2 (Next Week)
4. **Security improvements** (#6) - TLS, file permissions
5. **Complete high-priority TODOs** (#4) - Database backend, config updates
6. **Merge feature branches** (#7) - Review and clean up

### Sprint 3 (Month 1)
7. **Enhanced metrics** (#16) - Observability
8. **Performance optimization** (#14, #15) - Under load testing
9. **Documentation updates** (#10, #11) - Keep current

### Backlog (Future)
- Reduce complexity (#5)
- Line length cleanup (#13)
- Plugin hot reload (#9)
- Kubernetes improvements (#22)

---

## 🔍 Investigation Needed

### Questions to Answer:
1. **Relay Permission Issue:** Why is `isLocalDomain()` returning false for configured domains?
2. **Integration Tests:** Do we need TLS certs, or can we disable TLS for tests?
3. **TODOs:** Which TODOs are still relevant vs. outdated?
4. **Feature Branches:** Are ELE-* branches still active or can they be closed?
5. **SHA1 Usage:** Is it for legacy compatibility or can we remove it entirely?

---

## 📝 Notes

- **Testing:** Run `go test ./... -short` for quick validation
- **Full Tests:** Run `go test ./...` (without -short) after relay fix
- **Linting:** `golangci-lint run --timeout=5m` (works on CI, not local v2.8.0)
- **Branches:** `develop` for active work, merge to `main` when stable

**This file is for reference only - not tracked in git**
