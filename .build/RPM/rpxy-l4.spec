Name:           rpxy-l4
Version:        @BUILD_VERSION@
Release:        1%{?dist}
Summary:        A simple and ultrafast Layer 4 reverse-proxy serving multiple domain names, written in Rust

License:        MIT
URL:            https://github.com/junkurihara/rust-rpxy-l4
Source0:        @Source0@
BuildArch:      x86_64

Requires:       systemd

%description
This rpm installs rpxy-l4 into /usr/bin and sets up a systemd service.
rpxy-l4 is a Layer 4 reverse proxy supporting both TCP and UDP protocols
with protocol multiplexing capabilities for high-performance traffic forwarding.

# Prep section: Unpack the source
%prep
%autosetup

# Install section: Copy files to their destinations
%install
rm -rf %{buildroot}

# Create necessary directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/systemd/system
mkdir -p %{buildroot}%{_sysconfdir}/rpxy-l4
mkdir -p %{buildroot}%{_docdir}/rpxy-l4

# Copy files
cp rpxy-l4 %{buildroot}%{_bindir}/
cp rpxy-l4-start.sh %{buildroot}%{_bindir}/
cp rpxy-l4.service %{buildroot}%{_sysconfdir}/systemd/system/
cp config.toml %{buildroot}%{_sysconfdir}/rpxy-l4/
cp LICENSE README.md %{buildroot}%{_docdir}/rpxy-l4/

# Clean section: Remove buildroot
%clean
rm -rf %{buildroot}

# Pre-install script
%pre
# Create the rpxy-l4 user if it does not exist
if ! getent passwd rpxy-l4 >/dev/null; then
    useradd -r -s /sbin/nologin -d / -c "rpxy-l4 system user" rpxy-l4
fi

# Post-install script
%post
# Set ownership of config file to rpxy-l4 user
chown -R rpxy-l4:rpxy-l4 %{_sysconfdir}/rpxy-l4

# Reload systemd, enable and start rpxy-l4 service
%systemd_post rpxy-l4.service

# Pre-uninstall script
%preun
%systemd_preun rpxy-l4.service

# Post-uninstall script
%postun
%systemd_postun_with_restart rpxy-l4.service

# Only remove user and config on full uninstall
if [ $1 -eq 0 ]; then
    # Remove rpxy-l4 user
    userdel rpxy-l4

    # Remove the configuration directory if it exists
    [ -d %{_sysconfdir}/rpxy-l4 ] && rm -rf %{_sysconfdir}/rpxy-l4
fi

# Files section: List all files included in the package
%files
%license %{_docdir}/rpxy-l4/LICENSE
%doc %{_docdir}/rpxy-l4/README.md
%{_sysconfdir}/systemd/system/rpxy-l4.service
%attr(755, rpxy-l4, rpxy-l4) %{_bindir}/rpxy-l4
%attr(755, rpxy-l4, rpxy-l4) %{_bindir}/rpxy-l4-start.sh
%attr(644, rpxy-l4, rpxy-l4) %config(noreplace) %{_sysconfdir}/rpxy-l4/config.toml
