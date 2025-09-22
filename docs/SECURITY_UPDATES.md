# Security Updates and Dependency Management

This document outlines the security update process for the Elemta SMTP server and how to handle dependency vulnerabilities.

## Overview

The Elemta project uses automated security monitoring and manual review processes to ensure all dependencies are kept up-to-date and secure.

## Automated Security Monitoring

### GitHub Dependabot

We use GitHub Dependabot to automatically monitor for:
- **Go module vulnerabilities** - Weekly scans for security issues
- **Docker image vulnerabilities** - Weekly scans for base image updates
- **GitHub Actions vulnerabilities** - Weekly scans for workflow security

Configuration: `.github/dependabot.yml`

### Vulnerability Scanning

We use `govulncheck` to scan for known vulnerabilities in Go dependencies:

```bash
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Run vulnerability scan
govulncheck ./...

# Run with verbose output
govulncheck -v ./...
```

## Security Update Process

### 1. Automated Updates

Dependabot automatically creates pull requests for:
- **Minor and patch updates** - Grouped together for efficiency
- **Security updates** - Prioritized and labeled appropriately
- **Docker base image updates** - Scanned for vulnerabilities

### 2. Manual Review Process

For each security update:

1. **Review the vulnerability details** - Check CVE information and impact
2. **Test the update** - Run comprehensive test suite
3. **Verify functionality** - Ensure no breaking changes
4. **Deploy and monitor** - Update production with monitoring

### 3. Emergency Security Updates

For critical vulnerabilities (CVSS 7.0+):

1. **Immediate assessment** - Evaluate impact and exploitability
2. **Fast-track update** - Bypass normal review process if safe
3. **Emergency deployment** - Deploy to production immediately
4. **Post-incident review** - Document lessons learned

## Dependency Management

### Key Dependencies

Critical dependencies that require special attention:

- **`github.com/mattn/go-sqlite3`** - Database driver (CGO required)
- **`github.com/go-ldap/ldap/v3`** - LDAP authentication
- **`golang.org/x/crypto`** - Cryptographic functions
- **`github.com/prometheus/client_golang`** - Metrics collection
- **`github.com/redis/go-redis/v9`** - Caching and rate limiting

### Update Guidelines

#### Go Modules
```bash
# Check for outdated dependencies
go list -u -m all

# Update specific dependency
go get -u github.com/example/package@latest

# Update all dependencies
go get -u ./...

# Clean up unused dependencies
go mod tidy

# Verify no vulnerabilities
govulncheck ./...
```

#### Docker Images
```bash
# Update base images in Dockerfile
# Test with docker compose build
docker compose build elemta

# Verify functionality
docker compose up -d
./run_complete_tests.sh
```

## Security Best Practices

### 1. Dependency Pinning

- **Pin major versions** for critical dependencies
- **Use exact versions** for security-sensitive packages
- **Regular updates** for all dependencies

### 2. Vulnerability Monitoring

- **Weekly scans** with govulncheck
- **Automated alerts** via GitHub Dependabot
- **Manual reviews** for high-severity issues

### 3. Testing and Validation

- **Comprehensive test suite** after each update
- **Security-focused testing** for authentication and crypto
- **Performance testing** for critical path dependencies

### 4. Documentation and Communication

- **Security advisories** for critical vulnerabilities
- **Update changelog** for all security fixes
- **Team notifications** for high-priority updates

## Incident Response

### Security Vulnerability Response

1. **Immediate Assessment** (within 1 hour)
   - Evaluate severity and impact
   - Check for active exploitation
   - Determine update timeline

2. **Update Development** (within 24 hours for critical)
   - Create security update branch
   - Implement fix or update dependency
   - Test thoroughly

3. **Deployment** (within 48 hours for critical)
   - Deploy to staging environment
   - Run full test suite
   - Deploy to production

4. **Post-Incident** (within 1 week)
   - Document incident details
   - Review process improvements
   - Update security procedures

## Tools and Resources

### Vulnerability Databases
- [Go Vulnerability Database](https://pkg.go.dev/vuln)
- [CVE Database](https://cve.mitre.org/)
- [GitHub Security Advisories](https://github.com/advisories)

### Scanning Tools
- `govulncheck` - Go vulnerability scanner
- `trivy` - Container vulnerability scanner
- `snyk` - Multi-language vulnerability scanner

### Monitoring
- GitHub Dependabot alerts
- Automated CI/CD security scans
- Manual weekly vulnerability reviews

## Contact Information

For security-related issues:
- **Security Team**: security@elemta.com
- **Emergency Contact**: +1-XXX-XXX-XXXX
- **GitHub Issues**: Use "security" label for vulnerabilities

## Changelog

### 2025-09-22
- Initial security update process documentation
- Implemented GitHub Dependabot configuration
- Updated all dependencies to latest secure versions
- Added comprehensive vulnerability scanning

---

*This document is reviewed and updated quarterly or after any security incident.*
