# smoo development tasks

# Bump version across all packaging files
bump version:
    #!/usr/bin/env bash
    set -euo pipefail

    version="{{version}}"
    cargo_version="$version"
    package_version="$version"
    debian_version="$version"

    if [[ "$version" =~ _rc([0-9]+)$ ]]; then
        echo "Unsupported RC format '$version'. Use canonical semver '-rc.N' (for example: 0.0.1-rc.1)."
        exit 1
    fi

    if [[ "$version" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.([0-9]+)$ ]]; then
        base="${BASH_REMATCH[1]}"
        rc="${BASH_REMATCH[2]}"
        package_version="${base}_rc${rc}"
        debian_version="${base}~rc${rc}"
    fi

    echo "Bumping smoo to $version"

    # Cargo.toml workspace version
    sed -i "s/^version = \".*\"/version = \"${cargo_version}\"/" Cargo.toml

    # RPM spec
    sed -i "s/^Version:        .*/Version:        ${package_version}/" smoo.spec

    # Alpine APKBUILD (set base version, keep _git suffix for dev builds)
    sed -i "s/^pkgver=.*_git$/pkgver=${package_version}_git/" APKBUILD

    # Debian changelog (add new entry)
    sed -i "1s/.*/smoo (${debian_version}) UNRELEASED; urgency=medium/" debian/changelog

    # Update lockfile
    cargo generate-lockfile

    echo "Done. Files updated:"
    echo "  Cargo.toml"
    echo "  smoo.spec"
    echo "  APKBUILD"
    echo "  debian/changelog"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff"
    echo "  2. Commit: git commit -am 'v${version}'"
    echo "  3. Tag: git tag v${version}"
    echo "  4. Push: git push && git push --tags"
