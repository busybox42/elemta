#!/bin/bash
set -ex

# Package information
PACKAGE_NAME="elemta"
VERSION="0.0.1"
PACKAGE_DESCRIPTION="Elemta application"
PACKAGE_MAINTAINER="Your Name <your.email@example.com>"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/dist/ubuntu2204"

echo "Script directory: $SCRIPT_DIR"
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create temporary build directory
build_dir="./build_tmp/ubuntu"
rm -rf "$build_dir"
mkdir -p "$build_dir/DEBIAN"
mkdir -p "$build_dir/usr/local/bin"
mkdir -p "$build_dir/etc/$PACKAGE_NAME"
mkdir -p "$build_dir/usr/share/$PACKAGE_NAME"
mkdir -p "$build_dir/usr/lib/systemd/system"

echo "Copying application files..."
# Copy application files
if [ -f "../bin/$PACKAGE_NAME" ]; then
    cp "../bin/$PACKAGE_NAME" "$build_dir/usr/local/bin/"
    echo "Copied binary file"
else
    echo "Binary file not found: ../bin/$PACKAGE_NAME"
    exit 1
fi

if [ -f "../config/$PACKAGE_NAME.conf" ]; then
    cp "../config/$PACKAGE_NAME.conf" "$build_dir/etc/$PACKAGE_NAME/"
    echo "Copied config file"
else
    echo "Config file not found: ../config/$PACKAGE_NAME.conf"
    exit 1
fi

if [ -d "../data" ]; then
    cp -r ../data/* "$build_dir/usr/share/$PACKAGE_NAME/"
    echo "Copied data files"
else
    echo "Data directory not found: ../data"
    exit 1
fi

# Create DEBIAN control file
cat > "$build_dir/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: $PACKAGE_MAINTAINER
Description: $PACKAGE_DESCRIPTION
Depends: openssl (>= 1.1.1), zlib1g, libcurl4
EOF

# Create preinst script
cat > "$build_dir/DEBIAN/preinst" << EOF
#!/bin/sh
set -e

# Add user if it doesn't exist
if ! getent passwd $PACKAGE_NAME > /dev/null; then
  useradd --system --no-create-home --shell /sbin/nologin $PACKAGE_NAME
fi

exit 0
EOF

# Create postinst script
cat > "$build_dir/DEBIAN/postinst" << EOF
#!/bin/sh
set -e

# Set permissions
chown -R $PACKAGE_NAME:$PACKAGE_NAME /etc/$PACKAGE_NAME
chmod 750 /etc/$PACKAGE_NAME

# Enable and start service if systemd is available
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable $PACKAGE_NAME.service
  systemctl start $PACKAGE_NAME.service || true
fi

exit 0
EOF

# Create prerm script
cat > "$build_dir/DEBIAN/prerm" << EOF
#!/bin/sh
set -e

# Stop service if running
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop $PACKAGE_NAME.service
  systemctl disable $PACKAGE_NAME.service
fi

exit 0
EOF

# Create postrm script
cat > "$build_dir/DEBIAN/postrm" << EOF
#!/bin/sh
set -e

# Remove user only on complete uninstall
if [ "\$1" = "remove" ]; then
  if getent passwd $PACKAGE_NAME > /dev/null; then
    userdel $PACKAGE_NAME
  fi
fi

exit 0
EOF

# Make scripts executable
chmod +x "$build_dir/DEBIAN/preinst"
chmod +x "$build_dir/DEBIAN/postinst"
chmod +x "$build_dir/DEBIAN/prerm"
chmod +x "$build_dir/DEBIAN/postrm"

# Create systemd service file
cat > "$build_dir/usr/lib/systemd/system/$PACKAGE_NAME.service" << EOF
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

echo "Running Docker container to build the package..."
# Run Docker container to build the package
docker run --rm -v "$(pwd)/$build_dir:/build" -v "$(pwd)/$OUTPUT_DIR:/output" \
    ubuntu:22.04 /bin/bash -c "
        set -x
        apt-get update && \
        apt-get install -y dpkg-dev && \
        dpkg-deb --build /build /output/${PACKAGE_NAME}_${VERSION}_amd64.deb || { echo 'Build failed'; exit 1; }"

echo "Ubuntu package built successfully"
echo "Package is available in $OUTPUT_DIR/${PACKAGE_NAME}_${VERSION}_amd64.deb"

# Clean up
rm -rf "$build_dir" 