#!/bin/bash
set -ex

# Package information
PACKAGE_NAME="elemta"
VERSION="0.0.1"
PACKAGE_DESCRIPTION="Elemta application"
PACKAGE_MAINTAINER="Your Name <your.email@example.com>"
PACKAGE_LICENSE="MIT"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist/rhel9"

echo "Script directory: $SCRIPT_DIR"
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create temporary build directory
build_dir="./build_tmp/rhel9"
rm -rf "$build_dir"
mkdir -p "$build_dir"
mkdir -p "$build_dir/SOURCES"
mkdir -p "$build_dir/SPECS"
mkdir -p "$build_dir/BUILD"
mkdir -p "$build_dir/RPMS"
mkdir -p "$build_dir/SRPMS"
mkdir -p "$build_dir/BUILDROOT"

echo "Creating directory structure..."
# Create directory structure for the package
mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION"
mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin"
mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME"
mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME"
mkdir -p "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system"

echo "Copying application files..."
# Copy application files
if [ -f "../bin/$PACKAGE_NAME" ]; then
    cp "../bin/$PACKAGE_NAME" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/local/bin/"
    echo "Copied binary file"
else
    echo "Binary file not found: ../bin/$PACKAGE_NAME"
    exit 1
fi

if [ -f "../config/$PACKAGE_NAME.conf" ]; then
    cp "../config/$PACKAGE_NAME.conf" "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/etc/$PACKAGE_NAME/"
    echo "Copied config file"
else
    echo "Config file not found: ../config/$PACKAGE_NAME.conf"
    exit 1
fi

if [ -d "../data" ]; then
    cp -r ../data/* "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/share/$PACKAGE_NAME/"
    echo "Copied data files"
else
    echo "Data directory not found: ../data"
    exit 1
fi

echo "Creating systemd service file..."
# Create systemd service file
cat > "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
[Unit]
Description=$PACKAGE_DESCRIPTION
After=network.target

[Service]
Type=simple
User=$PACKAGE_NAME
Group=$PACKAGE_NAME
ExecStart=/usr/local/bin/$PACKAGE_NAME --config /etc/$PACKAGE_NAME/$PACKAGE_NAME.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "Creating tarball..."
# Create tarball
tar -czf "$build_dir/SOURCES/$PACKAGE_NAME-$VERSION.tar.gz" -C "$build_dir/SOURCES" "$PACKAGE_NAME-$VERSION"

echo "Creating spec file..."
# Create spec file
cat > "$build_dir/SPECS/package.spec" << EOF
Name:           $PACKAGE_NAME
Version:        $VERSION
Release:        1%{?dist}
Summary:        $PACKAGE_DESCRIPTION

License:        $PACKAGE_LICENSE
URL:            https://example.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
Requires:       openssl >= 3.0.0 zlib libcurl

%description
$PACKAGE_DESCRIPTION

%prep
%setup -q

%install
rm -rf \$RPM_BUILD_ROOT

# Create directories
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/%{name}
mkdir -p %{buildroot}/usr/share/%{name}
mkdir -p %{buildroot}/usr/lib/systemd/system

# Copy files from the source directory
install -m 755 usr/local/bin/%{name} %{buildroot}/usr/local/bin/
install -m 644 etc/%{name}/%{name}.conf %{buildroot}/etc/%{name}/
cp -r usr/share/%{name}/* %{buildroot}/usr/share/%{name}/
install -m 644 usr/lib/systemd/system/%{name}.service %{buildroot}/usr/lib/systemd/system/

%pre
# Add user if it doesn't exist
if ! getent passwd %{name} > /dev/null; then
  useradd --system --no-create-home --shell /sbin/nologin %{name}
fi

%post
# Set permissions
chown -R %{name}:%{name} /etc/%{name}
chmod 750 /etc/%{name}

# Enable and start service
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

# Remove user only on complete uninstall
if [ "\$1" = "0" ]; then
  if getent passwd %{name} > /dev/null; then
    userdel %{name}
  fi
fi

%files
%defattr(-,root,root,-)
%attr(755,root,root) /usr/local/bin/%{name}
%config(noreplace) /etc/%{name}/%{name}.conf
/usr/share/%{name}/*
%attr(644,root,root) /usr/lib/systemd/system/%{name}.service

%changelog
* $(date "+%a %b %d %Y") Package Maintainer <maintainer@example.com> - $VERSION-1
- Initial package
EOF

echo "Running Docker container to build the package..."
# Run Docker container to build the package
docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
    almalinux:9 /bin/bash -c "
        set -x
        cd /build && \
        dnf install -y rpm-build rpmdevtools gcc make && \
        rpmbuild --define '_topdir /build' -ba SPECS/package.spec && \
        cp /build/RPMS/*/*.rpm /output/ || { echo 'Build failed'; find /build -name '*.log' -exec cat {} \; 2>/dev/null || echo 'No build logs found'; exit 1; }"

echo "RHEL 9 package built successfully"
echo "Package is available in $OUTPUT_DIR"

# Clean up
rm -rf "$build_dir" 