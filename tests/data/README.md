# Test Data Files

This directory contains data files used for testing the Elemta SMTP server.

## Available Files

- **eicar.txt**: EICAR test file for antivirus testing
- **gtube.txt**: GTUBE test file for spam filter testing

## EICAR Test File

The EICAR test file is a standard file used to test antivirus systems. It's not an actual virus, but it's designed to be detected by antivirus software as if it were.

The file contains the following string:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

## GTUBE Test File

The GTUBE (Generic Test for Unsolicited Bulk Email) test file is a standard file used to test spam filters. It's not actual spam, but it's designed to be detected by spam filters as if it were.

The file contains the following string:
```
XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
```

## Using Test Data

The test files are used by the security test scripts to verify that the security functionality is working correctly:

```bash
# Test ClamAV with EICAR
docker exec elemta_clamav_1 clamdscan /tmp/eicar.txt

# Test Rspamd with GTUBE
docker exec elemta_rspamd_1 rspamc scan /tmp/gtube.txt
```

You can also use the verification script to check the entire monitoring stack:

```bash
./scripts/verify-monitoring-stack.sh
```

**Note**: Some systems may automatically quarantine or delete the EICAR test file. This is expected behavior and indicates that the antivirus system is working correctly. 