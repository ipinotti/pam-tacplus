#
# spec file for package 'name' (version 'v')
#
# The following software is released as specified below.
# This spec file is released to the public domain.
# (c) Lincom Software Team

# Basic Information
Name: pam_tacplus
Version: 1.3.2
Release: 1%{?dist}
Summary: PAM Tacacs+ module
Group: System
License: GPL
URL: http://tacplus.sourceforge.net/

# Packager Information
Packager: NRB

# Build Information
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# Source Information
Source0: http://downloads.sourceforge.net/project/tacplus/pam_tacplus/pam_tacplus-1.3.2.tar.gz

# Dependency Information
BuildRequires: gcc binutils pam-devel
Requires: pam

%description
PAM Tacacs+ module based on code produced by Pawel Krawczyk <kravietz@ceti.com.pl> and Jeroen Nijhof <jeroen@nijhofnet.nl>

%prep
%setup -q -a 0

%build
./configure
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc/pam.d,lib/security}

install -m 755 pam_tacplus.so \
               $RPM_BUILD_ROOT/lib/security/

install -m 644 sample.pam $RPM_BUILD_ROOT/etc/pam.d/tacacs

chmod 755 $RPM_BUILD_ROOT/lib/security/*.so*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /lib/security/*.so*
%attr(0644,root,root) %config(noreplace) /etc/pam.d/tacacs
%doc AUTHORS COPYING README ChangeLog

%changelog
* Mon Mar 17 2010 beNDon <benoit.donneaux@gmail.com> 1.3.1r
- Autotools aware
- spec file added for RPM building
