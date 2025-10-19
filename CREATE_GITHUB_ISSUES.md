# GitHub Issues Creation Guide - Elemta Deep Analysis

**Status**: 6 issues ready to create
**Date**: 2025-10-18
**Repository**: https://github.com/busybox42/elemta

## Quick Links

- **Create Issue**: https://github.com/busybox42/elemta/issues/new
- **View Issues**: https://github.com/busybox42/elemta/issues
- **Labels**: https://github.com/busybox42/elemta/labels

---

## Issue #1 (HIGH Priority)

**Title**: `[SMTP] Replace fmt.Printf Debug Logging with Structured slog`

**Labels**: `technical-debt`, `enhancement`, `priority:high`

**Body**:
**Problem**

Production-ready structured logging is not consistently used across the SMTP server. Debug statements use fmt.Printf which writes directly to stdout without log levels, context, or configurability. This creates operational challenges in production environments where logs need filtering, correlation, and integration with log aggregation systems.

**Current State**

Evidence from codebase analysis:
- **69 instances** of fmt.Printf/fmt.Println in internal/smtp/ alone
- Located in critical paths: server.go (21 instances), resource_manager.go (26 instances)

Example violations:
```go
// internal/smtp/server.go:528
fmt.Printf("DEBUG: acceptConnections goroutine started\n")

// internal/smtp/resource_manager.go:657  
fmt.Printf("DEBUG: CanAcceptConnection called for %s\n", remoteAddr)
```

**Files Affected:**
- `/internal/smtp/server.go` (lines 528, 556, 565, 571, 584, etc. - 21 instances)
- `/internal/smtp/resource_manager.go` (lines 657-768 - 26 instances)
- `/internal/smtp/memory_manager.go` (16 instances)
- `/internal/smtp/config.go` (4 instances)
- `/internal/smtp/metrics.go` (2 instances)

**Expected Outcome**

All debug/diagnostic logging should use the structured slog logger that's already available via `s.slogger` in the Server struct. This enables:
- Configurable log levels
- Structured fields for filtering
- Context propagation
- Integration with centralized logging systems

**Technical Details**

The Server struct already has `slogger *slog.Logger` available. Replace:
```go
fmt.Printf("DEBUG: %s\n", msg)
```

With:
```go
s.slogger.Debug(msg, "field", value)
```

**Acceptance Criteria**
- [ ] All fmt.Printf debug statements in internal/smtp/ replaced with slog.Debug()
- [ ] Structured fields added for key values (IP addresses, session IDs, etc.)
- [ ] Log level configurable via config file
- [ ] No debug output in production unless explicitly enabled
- [ ] CI check added to prevent new fmt.Printf in production code

**Priority Justification**

**HIGH** - This blocks production deployment as:
- Debug logs cannot be disabled (performance impact)
- No log correlation possible (troubleshooting impact)
- Cannot integrate with ELK/Grafana Loki (observability impact)

**Verification**
```bash
$ grep -r "fmt.Printf\|fmt.Println" internal/smtp/*.go | wc -l
69
```

**Related Issues**

Related to #10 (logging security), but #10 focuses on log injection while this focuses on structured logging infrastructure.

---

## Issue #2 (MEDIUM Priority)

**Title**: `[Plugin] Remove context.TODO() from Security-Critical Operations`

**Labels**: `technical-debt`, `Plugin`, `priority:medium`

**Body**:

**Problem**

Plugin virus/spam scanning operations use `context.TODO()` instead of propagating proper context, preventing timeout enforcement and cancellation propagation in security-critical code paths.

**Current State**

```go
// internal/plugin/plugin.go:161
result, err := scanner.ScanBytes(context.TODO(), data)

// internal/plugin/plugin.go:291  
result, err := scanner.ScanBytes(context.TODO(), data)
```

**Files Affected:**
- `/internal/plugin/plugin.go:161` (virus scanning)
- `/internal/plugin/plugin.go:291` (spam scanning)

**Expected Outcome**

Pass actual context from calling functions to enable:
- Timeout enforcement for hanging scans
- Cancellation when connection closes
- Request tracing and correlation

**Acceptance Criteria**
- [ ] context.TODO() replaced with ctx parameter in ScanEmail()
- [ ] Context propagated from SMTP session to plugin execution
- [ ] Timeout tests added for long-running scans
- [ ] CI check to prevent new context.TODO() in production code

**Priority**: MEDIUM - Security operations should respect timeouts

**Verification**:
```bash
$ grep -n "context.TODO()" internal/plugin/plugin.go
161:    result, err := scanner.ScanBytes(context.TODO(), data)
291:    result, err := scanner.ScanBytes(context.TODO(), data)
```

---

## Issue #3 (HIGH Priority)

**Title**: `[Testing] Increase Test Coverage for Production-Critical Packages`

**Labels**: `enhancement`, `testing`, `priority:high`

**Body**:

**Problem**

Test coverage is insufficient for production deployment. Only 27% of internal packages have test files.

**Current State**
- **26 test files** vs **97 source files** = 27% coverage
- **117 test functions** total

**Packages with ZERO test coverage:**
- `/internal/zimbra/` (4 source files)
- `/internal/message/` (1 source file)
- `/internal/server/` (1 source file)
- `/internal/example/` (1 source file)

**Packages with LIMITED coverage:**
- `/internal/api/` (3 source, 1 test)
- `/internal/antivirus/` (2 source, no comprehensive tests)
- `/internal/logging/` (4 source, no dedicated tests)

**Expected Outcome**
- Minimum 60% line coverage for production packages
- 100% coverage for security-critical code
- Integration tests for all major subsystems

**Acceptance Criteria**
- [ ] Test coverage report generated via `go test -coverprofile=coverage.out ./...`
- [ ] Critical packages (auth, smtp, queue, api) reach 70%+ coverage
- [ ] Integration test suite added
- [ ] CI fails if coverage drops below 60%
- [ ] Coverage badge added to README.md

**Priority**: HIGH - Insufficient testing risks production stability

**Verification**:
```bash
$ find ./internal -name "*_test.go" | wc -l
26
$ find ./internal -name "*.go" ! -name "*_test.go" | wc -l  
97
```

---

## Issue #4 (CRITICAL Priority)

**Title**: `[Production] Add Graceful Shutdown and Cleanup Testing`

**Labels**: `bug`, `testing`, `component:smtp-server`, `priority:critical`

**Body**:

**Problem**

No automated tests verify graceful shutdown behavior, risking data loss and connection handling issues in production deployments (especially Kubernetes).

**Current State**

Zero tests for:
- ❌ Signal handling (SIGTERM, SIGINT)
- ❌ Active connection draining  
- ❌ Queue persistence during shutdown
- ❌ Resource cleanup (goroutines, file descriptors)
- ❌ Metrics final flush

**Verification**:
```bash
$ grep -r "TestShutdown\|TestGraceful\|SIGTERM" internal/ tests/
# No results found
```

**Expected Outcome**

Comprehensive shutdown testing covering:
1. Signal handling - SIGTERM/SIGINT properly caught
2. Connection draining - Active connections complete gracefully
3. Queue persistence - All queued messages saved to disk
4. Resource cleanup - No goroutine leaks, file descriptors closed
5. Metrics flush - Final metrics exported before shutdown
6. Kubernetes compatibility - Proper K8s pod termination

**Files That Need Testing:**
- `/internal/smtp/server.go` - Server.Close() method
- `/cmd/elemta/commands/server.go` - Signal handling
- `/internal/queue/manager.go` - Queue persistence
- `/internal/smtp/worker_pool.go` - Worker cleanup

**Acceptance Criteria**
- [ ] TestGracefulShutdown() - signal handling
- [ ] TestConnectionDraining() - active connections
- [ ] TestQueuePersistence() - no message loss
- [ ] TestResourceCleanup() - no leaks
- [ ] TestMetricsFinalFlush() - metrics export
- [ ] TestKubernetesTermination() - K8s compatibility
- [ ] Documentation added for shutdown behavior

**Priority**: CRITICAL (P0) - Data loss risk in production

---

## Issue #5 (MEDIUM Priority)

**Title**: `[API] Add Centralized Error Response Structure`

**Labels**: `enhancement`, `component:api`, `priority:medium`, `good first issue`

**Body**:

**Problem**

No standardized error response format for REST API endpoints, making client integration difficult.

**Expected Outcome**

Implement RFC 7807 Problem Details JSON:

```go
type ErrorResponse struct {
    Type     string            `json:"type"`
    Title    string            `json:"title"`
    Status   int               `json:"status"`
    Detail   string            `json:"detail"`
    Instance string            `json:"instance"`
    Fields   map[string]string `json:"fields,omitempty"`
}
```

**Example**:
```go
WriteError(w, ErrorResponse{
    Type:     "https://elemta.io/errors/validation",
    Title:    "Validation Failed",
    Status:   http.StatusBadRequest,
    Detail:   "Email address format is invalid",
    Instance: requestID,
})
```

**Files Affected:**
- `/internal/api/server.go` - Update error responses
- `/internal/api/errors.go` - New file

**Acceptance Criteria**
- [ ] ErrorResponse struct defined (RFC 7807)
- [ ] All API handlers use consistent errors
- [ ] Request correlation IDs included
- [ ] OpenAPI spec updated
- [ ] Documentation added

**Priority**: MEDIUM - Improves API usability

**References**:
- [RFC 7807](https://datatracker.ietf.org/doc/html/rfc7807)

---

## Issue #6 (MEDIUM Priority)

**Title**: `[CI/CD] Add Test Coverage Reporting and Enforcement`

**Labels**: `enhancement`, `devops`, `testing`, `priority:medium`

**Body**:

**Problem**

No test coverage tracking in CI/CD pipeline. Current coverage: ~27%

**Current State**
- ✅ Security scanning (govulncheck, Trivy)
- ✅ Dependency auditing
- ❌ No coverage reporting
- ❌ No coverage thresholds
- ❌ No coverage history

**Expected Outcome**

Add coverage workflow:
```yaml
- name: Run tests with coverage
  run: |
    go test -coverprofile=coverage.out -covermode=atomic ./...
    
- name: Coverage gate
  run: |
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
    if [[ ${COVERAGE%\%} < 60 ]]; then exit 1; fi
```

**Acceptance Criteria**
- [ ] Coverage report on every push/PR
- [ ] CI fails if coverage < 60%
- [ ] Coverage comments on PRs
- [ ] Coverage badge in README
- [ ] Codecov integration
- [ ] Historical tracking

**Priority**: MEDIUM - Prevents technical debt accumulation

**Implementation**:
1. Create `.github/workflows/coverage.yml`
2. Set threshold to 60%
3. Add Codecov (free for open source)
4. Add coverage badge to README

---

## Creation Checklist

After creating each issue:
- [ ] Verify labels are applied
- [ ] Assign to milestone ("Production Ready" or "Code Quality")
- [ ] Cross-reference related issues in comments
- [ ] Add to GitHub project board (if using)

## Priority Summary

| Priority | Count | Issues |
|----------|-------|--------|
| CRITICAL | 1 | #4 (Graceful Shutdown) |
| HIGH | 2 | #1 (Logging), #3 (Coverage) |
| MEDIUM | 3 | #2 (context.TODO), #5 (API Errors), #6 (CI Coverage) |

## Implementation Order

1. **Week 1-2**: Issue #4 (Graceful shutdown) - CRITICAL
2. **Week 2-3**: Issue #1 (Structured logging) - HIGH  
3. **Week 3-4**: Issue #3 (Test coverage) - HIGH
4. **Week 4-5**: Issue #6 (CI coverage) - MEDIUM
5. **Week 5-6**: Issue #2 (context.TODO) - MEDIUM
6. **Week 6-7**: Issue #5 (API errors) - MEDIUM

---

**All issues verified against existing 50 GitHub issues - no duplicates.**
**All issues evidence-based with specific file:line references from code analysis.**
