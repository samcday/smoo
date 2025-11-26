%bcond check 1
%bcond vendor 1
%bcond host 1
%bcond gadget 1
%global cargo_install_lib 0
%if %{with vendor}
%global _cargo_generate_buildrequires 0
%endif

%if !%{with host} && !%{with gadget}
%{error:At least one of --with host or --with gadget must be enabled}
%endif

%global _smoo_cargo_packages %{nil}
%if %{with host}
%global _smoo_cargo_packages %{_smoo_cargo_packages} -p smoo-host-cli
%endif
%if %{with gadget}
%global _smoo_cargo_packages %{_smoo_cargo_packages} -p smoo-gadget-cli
%endif

Name:           smoo
Version:        0.0.1
Release:        %autorelease
Summary:        Inverted USB mass-storage host/gadget utilities
License:        GPL-3.0-only
URL:            https://github.com/samcday/smoo
Source:         %{url}/archive/%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  clang-devel
%if %{with host}
BuildRequires:  libusbx-devel
%endif

%description
smoo provides both sides of an inverted USB mass-storage protocol: a gadget
implementation that serves block data over FunctionFS + ublk, and a host
implementation that drives it over USB.

%if %{with gadget}
%package gadget
Summary:        smoo gadget CLI
Requires:       %{name}%{?_isa}

%description gadget
Device-side CLI that exposes a smoo gadget backed by FunctionFS + ublk.
%endif

%if %{with host}
%package host
Summary:        smoo host CLI
Requires:       %{name}%{?_isa}

%description host
Host-side CLI that speaks the smoo USB protocol over rusb.
%endif

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
%cargo_build -- %{_smoo_cargo_packages}
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

%install
%if %{with gadget}
install -Dpm0755 target/rpm/smoo-gadget-cli \
    %{buildroot}%{_bindir}/smoo-gadget
%endif
%if %{with host}
install -Dpm0755 target/rpm/smoo-host-cli \
    %{buildroot}%{_bindir}/smoo-host
%endif

%if %{with check}
%check
%cargo_test -- %{_smoo_cargo_packages}
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%license crates/smoo-proto/LICENSE-MIT
%doc README.md

%if %{with gadget}
%files gadget
%{_bindir}/smoo-gadget
%endif

%if %{with host}
%files host
%{_bindir}/smoo-host
%endif

%changelog
%autochangelog
