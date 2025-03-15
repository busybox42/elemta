# Test Data Files

This directory contains data files used for testing the Elemta SMTP server.

## Available Files

- **eicar.txt**: EICAR test file for antivirus testing

## EICAR Test File

The EICAR test file is a standard file used to test antivirus systems. It's not an actual virus, but it's designed to be detected by antivirus software as if it were.

The file contains the following string:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

## Using Test Data

The EICAR test file is used by the security test script to verify that the antivirus functionality is working correctly:

```bash
python3 tests/python/test_security.py --test virus
```

**Note**: Some systems may automatically quarantine or delete the EICAR test file. This is expected behavior and indicates that the antivirus system is working correctly. 