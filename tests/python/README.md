# Elemta Python Tests

## End-to-End (e2e) Testing

All e2e tests are now in `tests/python/e2e/` and use pytest. These cover:
- SMTP protocol (plain, STARTTLS)
- AUTH (success/fail)
- Plugin effects (ClamAV, Rspamd)
- API and metrics endpoints

To run all e2e tests:

```sh
cd tests/python/e2e
pytest -v
```

## Deprecated Scripts

The old ad-hoc scripts (`test_smtp.py`, `test_smtp_auth.py`, `test_security.py`) have been removed in favor of the new pytest-based suite. 