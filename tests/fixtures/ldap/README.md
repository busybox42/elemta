# LDAP Test Fixtures

This directory contains LDIF files for testing LDAP authentication and user management.

## Files

- **`demo-users.ldif`** - Multiple demo users for testing
- **`demo-user.ldif`** - Single demo user (demo@example.com)
- **`local-user.ldif`** - Local user with full attributes
- **`local-user-simple.ldif`** - Minimal local user
- **`local-user-only.ldif`** - Standalone local user
- **`change-password.ldif`** - Password change operation
- **`ou-people.ldif`** - Organizational unit structure

## Usage

These fixtures are used by:
- Integration tests in `tests/`
- Docker LDAP bootstrap in `docker/ldap/bootstrap.ldif`
- Manual testing with `ldapadd` commands

## Loading Fixtures

```bash
# Load into running LDAP container
docker exec elemta-ldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f /path/to/fixture.ldif

# Or use the init script
./scripts/init-ldap-users.sh
```

## Credentials

Default test users:
- **demo/demo123** - Basic demo user
- **user/password** - Standard test user
- **sender/password** - Email sender
- **recipient/password** - Email recipient

