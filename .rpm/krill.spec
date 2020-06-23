%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: krill
Summary: Resource Public Key Infrastructure (RPKI) daemon
Version: @@VERSION@@
Release: @@RELEASE@@
License: MPLv2.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://www.nlnetlabs.nl/projects/rpki/krill/

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
