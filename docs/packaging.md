# Install package builders

The package builder creates native packages that contain the desktop and command-line applications.
It reads the version from the workspace manifest.
It also generates an inventory of third-party licenses from the locked dependency graph.
Review that inventory before public distribution.

Run all commands from the repository root.
Packages are written to `dist/packages` by default.
Use `--output PATH` to select another directory.
Use `--no-build` to package release binaries that already exist.
Use `--target TRIPLE` to select an installed Rust compilation target.

## Ubuntu and Debian

Install the build requirements:

```sh
sudo apt-get install build-essential pkg-config libpcsclite-dev libgtk-3-dev libxkbcommon-x11-dev python3 dpkg-dev
```

Build the Debian package:

```sh
python3 packaging/build.py deb
```

Install the resulting package:

```sh
sudo apt install ./dist/packages/cardpeek-ng_VERSION_amd64.deb
```

The package declares the required PC/SC and X11 runtime libraries.
It recommends the PC/SC daemon.
The desktop launcher and application icon are installed in the standard system locations.

## Red Hat, Alma Linux, and Fedora

Install the build requirements:

```sh
sudo dnf install gcc gcc-c++ make pkgconf-pkg-config pcsc-lite-devel gtk3-devel python3 rpm-build
```

Build the RPM package:

```sh
python3 packaging/build.py rpm
```

Install the resulting package:

```sh
sudo dnf install ./dist/packages/cardpeek-ng-VERSION-1.x86_64.rpm
```

RPM automatic dependency processing supplies shared-library requirements.
The package also requires the PC/SC runtime and recommends PC/SC CCID reader support.

## Windows

Build the MSI on Windows.
Install Python 3 and the WiX toolset version 4:

```powershell
dotnet tool install --global wix --version 4.0.6
wix extension add WixToolset.UI.wixext/4.0.6
```

Build the installer:

```powershell
python packaging/build.py msi
```

The MSI installs both executables, creates a Start menu shortcut, and adds the application directory to the system path.
It supports major upgrades and per-machine installation.
The Windows Smart Card service supplies PC/SC support.

The workflow and local builder produce an unsigned MSI.
Sign release MSIs with the organisation's code-signing process before public distribution.

## macOS

Build the installer package on macOS with the Xcode command-line tools and Python 3:

```sh
python3 packaging/build.py pkg
```

The builder creates `Cardpeek-ng.app` with both executables and a multi-resolution icon.
It installs the application in `/Applications` and a `cardpeek` command link in `/usr/local/bin`.
The system CryptoTokenKit framework supplies PC/SC support.

For a signed release, provide both Developer ID identities:

```sh
python3 packaging/build.py pkg \
  --codesign-identity "Developer ID Application: Example" \
  --installer-identity "Developer ID Installer: Example"
```

For notarization, first store App Store Connect credentials with `xcrun notarytool store-credentials`.
Then add `--notary-profile PROFILE`.
The builder submits the signed package, waits for approval, and staples the ticket.

## Package checks

On Ubuntu or Debian, inspect a package without installing it:

```sh
dpkg-deb --info dist/packages/cardpeek-ng_*.deb
dpkg-deb --contents dist/packages/cardpeek-ng_*.deb
```

On Red Hat or Alma Linux:

```sh
rpm -qip dist/packages/cardpeek-ng-*.rpm
rpm -qlp dist/packages/cardpeek-ng-*.rpm
```

On macOS:

```sh
pkgutil --check-signature dist/packages/Cardpeek-ng-*.pkg
pkgutil --expand-full dist/packages/Cardpeek-ng-*.pkg /tmp/cardpeek-package
```

Test physical reader access with a disposable test card.
Package tests do not replace the hardware checks in [the hardware test guide](hardware-tests.md).
