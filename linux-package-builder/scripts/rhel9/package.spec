Name:           __PACKAGE_NAME__
Version:        __PACKAGE_VERSION__
Release:        1%{?dist}
Summary:        __PACKAGE_DESCRIPTION__

License:        __PACKAGE_LICENSE__
URL:            https://example.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
Requires:       __PACKAGE_DEPENDENCIES__

%description
__PACKAGE_DESCRIPTION__

%prep
%setup -q

%install
rm -rf $RPM_BUILD_ROOT

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
if [ "$1" = "0" ]; then
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
* __DATE__ Package Maintainer <maintainer@example.com> - __PACKAGE_VERSION__-1
- Initial package 