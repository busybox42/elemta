# Elemta Linux Package Builder

This directory contains scripts to build Linux packages for the Elemta application.

## Package Types

The following package types are supported:

- RPM packages for RHEL/CentOS 8
- RPM packages for RHEL/CentOS 9
- DEB packages for Debian 11
- DEB packages for Ubuntu 22.04

## Prerequisites

- Docker (for building packages)
- Bash shell

## Directory Structure

```
linux-package-builder/
├── build_all.sh         # Script to build all packages
├── build_rpm.sh         # Script to build RPM packages for RHEL/CentOS 8
├── build_rhel9.sh       # Script to build RPM packages for RHEL/CentOS 9
├── build_debian.sh      # Script to build DEB packages for Debian 11
├── build_ubuntu.sh      # Script to build DEB packages for Ubuntu 22.04
├── check_files.sh       # Script to check for required files
├── README.md            # This documentation file
└── SUMMARY.md           # Summary of package building implementation
```

When the build scripts are run, they will create the following directories:

```
linux-package-builder/
├── dist/                # Output directory for built packages
│   ├── rhel8/           # RHEL/CentOS 8 packages
│   ├── rhel9/           # RHEL/CentOS 9 packages
│   ├── debian11/        # Debian 11 packages
│   └── ubuntu2204/      # Ubuntu 22.04 packages
└── build_tmp/           # Temporary build directory
```

## Required Files

The build scripts expect the following files to be present in the parent directory:

```
elemta/
├── bin/
│   └── elemta           # The Elemta binary
├── config/
│   └── elemta.conf      # Configuration file
└── data/                # Data directory
```

If these files are not present, the `check_files.sh` script will create dummy files for testing purposes.

## Building Packages

### Building All Packages

To build all packages, run:

```bash
./build_all.sh
```

This will build all package types and place them in the appropriate subdirectories under the `dist` directory.

### Building Specific Package Types

To build a specific package type, run one of the following scripts:

```bash
# Build RPM packages for RHEL/CentOS 8
./build_rpm.sh

# Build RPM packages for RHEL/CentOS 9
./build_rhel9.sh

# Build DEB packages for Debian 11
./build_debian.sh

# Build DEB packages for Ubuntu 22.04
./build_ubuntu.sh
```

## Package Versions

All packages are built with version 0.0.1.

## Package Contents

Each package includes:

- The Elemta binary file
- Configuration files
- Data files
- Systemd service file

## Installation

### RPM Packages

```bash
# RHEL/CentOS 8
sudo rpm -i dist/rhel8/elemta-0.0.1-1.el8.x86_64.rpm

# RHEL/CentOS 9
sudo rpm -i dist/rhel9/elemta-0.0.1-1.el9.x86_64.rpm
```

### DEB Packages

```bash
# Debian 11
sudo dpkg -i dist/debian11/elemta_0.0.1_amd64.deb

# Ubuntu 22.04
sudo dpkg -i dist/ubuntu2204/elemta_0.0.1_amd64.deb
```

## Service Management

After installation, the Elemta service can be managed using systemd:

```bash
# Start the service
sudo systemctl start elemta

# Stop the service
sudo systemctl stop elemta

# Enable the service to start at boot
sudo systemctl enable elemta

# Check the service status
sudo systemctl status elemta
```

## Uninstallation

### RPM Packages

```bash
sudo rpm -e elemta
```

### DEB Packages

```bash
sudo dpkg -r elemta
```

## Troubleshooting

If you encounter issues with the package building process, try the following:

1. Check if the required files exist using `./check_files.sh`
2. Make sure Docker is installed and running
3. Check the build logs in the `build_tmp` directory 