%bcond_without check
%bcond_without vendor
%global cargo_install_lib 0
%if %{with vendor}
%global _cargo_generate_buildrequires 0
%endif

Name:           smoo
Version:        0.0.2_rc6
Release:        %autorelease
Summary:        Inverted USB mass-storage host/gadget utilities
License:        GPL-3.0-only
URL:            https://github.com/samcday/smoo
Source:         %{url}/archive/%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  clang-devel
BuildRequires:  pkgconfig(openssl)

%description
smoo provides both sides of an inverted USB mass-storage protocol: a gadget
implementation that serves block data over FunctionFS + ublk, and a host
implementation that drives it over USB.

%package gadget
Summary:        smoo gadget CLI
Requires:       %{name}%{?_isa}

%description gadget
Device-side CLI that exposes a smoo gadget backed by FunctionFS + ublk.

%package host
Summary:        smoo host CLI
Requires:       %{name}%{?_isa}

%description host
Host-side CLI that speaks the smoo USB protocol over rusb.

%package dracut
Summary:        dracut module for smoo gadget root storage
BuildArch:      noarch
Requires:       dracut
Requires:       %{name}-gadget = %{version}-%{release}

%description dracut
dracut module that starts smoo-gadget in the initrd so a USB host can
serve the root filesystem as a ublk block device.

%prep
%autosetup -n %{name}-%{version} -p1
%if %{with vendor}
%{__cargo} vendor --locked --versioned-dirs vendor
%cargo_prep -v vendor
%else
%cargo_prep
%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
%cargo_build
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

%install
install -Dpm0755 target/rpm/smoo-gadget \
    %{buildroot}%{_bindir}/smoo-gadget
install -Dpm0755 target/rpm/smoo-host \
    %{buildroot}%{_bindir}/smoo-host
install -Dpm0755 dracut/modules.d/90smoo/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/module-setup.sh
install -Dpm0755 dracut/modules.d/90smoo/parse-smoo.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/parse-smoo.sh
install -Dpm0755 dracut/modules.d/90smoo/smoo-gadget-initrd-start.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/smoo-gadget-initrd-start.sh
install -Dpm0755 dracut/modules.d/90smoo/smoo-gadget-initrd-stop.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/smoo-gadget-initrd-stop.sh
install -Dpm0644 dracut/modules.d/90smoo/60-smoo-root.rules \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/60-smoo-root.rules
install -Dpm0644 dracut/modules.d/90smoo/smoo-root-storage.service \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90smoo/smoo-root-storage.service
install -Dpm0644 dracut/modules.d/90smoo/smoo-root-storage.service \
    %{buildroot}%{_prefix}/lib/systemd/system/smoo-root-storage.service

%if %{with check}
%check
%cargo_test
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%license crates/smoo-proto/LICENSE-MIT
%doc README.md

%files gadget
%{_bindir}/smoo-gadget

%files host
%{_bindir}/smoo-host

%files dracut
%doc docs/DRACUT.md
%{_prefix}/lib/systemd/system/smoo-root-storage.service
%dir %{_prefix}/lib/dracut/modules.d/90smoo
%{_prefix}/lib/dracut/modules.d/90smoo/*

%changelog
%autochangelog
