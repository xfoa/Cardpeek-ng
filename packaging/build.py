#!/usr/bin/env python3
import argparse
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
VERSION = re.search(r'^\s*version\s*=\s*"([^"]+)"', MANIFEST, re.MULTILINE).group(1)
PRODUCT = "Cardpeek-ng"
PACKAGE = "cardpeek-ng"
URL = "https://github.com/xfoa/Cardpeek-ng"
IDENTIFIER = "io.github.xfoa.cardpeek-ng"


def run(*arguments, **kwargs):
    print("+", " ".join(str(argument) for argument in arguments), flush=True)
    return subprocess.run(
        [str(argument) for argument in arguments], cwd=ROOT, check=True, **kwargs
    )


def require(command):
    path = shutil.which(command)
    if path is None:
        raise SystemExit(f"Required command is not installed: {command}")
    return path


def cargo_directory(target):
    directory = ROOT / "target"
    if target:
        directory /= target
    return directory / "release"


def build_binaries(args):
    if args.no_build:
        return
    command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--package",
        "cardpeek-cli",
        "--package",
        "cardpeek-desktop",
    ]
    if args.target:
        command.extend(("--target", args.target))
    run(*command)


def copy_file(source, destination, executable=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if executable:
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def binaries(args, suffix=""):
    directory = cargo_directory(args.target)
    paths = {
        "desktop": directory / f"cardpeek-desktop{suffix}",
        "cli": directory / f"cardpeek{suffix}",
    }
    for path in paths.values():
        if not path.is_file():
            raise SystemExit(f"Application binary does not exist: {path}")
    return paths


def reset_directory(path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def generate_notices(destination):
    metadata = json.loads(
        run(
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--locked",
            capture_output=True,
            text=True,
        ).stdout
    )
    lines = [
        "# Third-party notices",
        "",
        "This inventory is generated from the locked Rust dependency graph.",
        "Review it before public distribution.",
        "",
    ]
    packages = sorted(metadata["packages"], key=lambda package: (package["name"], package["version"]))
    workspace_members = set(metadata["workspace_members"])
    for package in packages:
        if package["id"] in workspace_members:
            continue
        manifest_path = Path(package["manifest_path"])
        lines.extend(
            (
                f"## {package['name']} {package['version']}",
                "",
                f"Source: {package.get('source') or 'local'}",
                f"Declared license: {package.get('license') or 'not declared'}",
            )
        )
        if package.get("repository"):
            lines.append(f"Repository: {package['repository']}")
        lines.append("")
        directory = manifest_path.parent
        candidates = []
        explicit = package.get("license_file")
        if explicit:
            candidates.append(directory / explicit)
        else:
            candidates = sorted(
                path
                for path in directory.iterdir()
                if path.is_file()
                and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))
            )
        if not candidates:
            lines.extend(("No license text is included in the published crate.", ""))
            continue
        for candidate in candidates:
            lines.extend((f"### {candidate.name}", "", candidate.read_text(errors="replace"), ""))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")


def copy_legal(directory, notices):
    for name in ("LICENSE", "NOTICE.md"):
        copy_file(ROOT / name, directory / name)
    copy_file(notices, directory / "THIRD_PARTY_NOTICES.md")


def host_architecture():
    machine = platform.machine()
    return {"AMD64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def linux_architecture(args, package_format):
    machine = args.target.split("-")[0] if args.target else host_architecture()
    architectures = {
        "deb": {"x86_64": "amd64", "aarch64": "arm64"},
        "rpm": {"x86_64": "x86_64", "aarch64": "aarch64"},
    }
    try:
        return architectures[package_format][machine]
    except KeyError as error:
        raise SystemExit(f"Unsupported {package_format} architecture: {machine}") from error


def linux_payload(args, root):
    paths = binaries(args)
    copy_file(paths["desktop"], root / "usr/bin/cardpeek-desktop", executable=True)
    copy_file(paths["cli"], root / "usr/bin/cardpeek", executable=True)
    copy_file(
        ROOT / "resources/cardpeek-ng.desktop",
        root / "usr/share/applications/cardpeek-ng.desktop",
    )
    copy_file(
        ROOT / "resources/icon.png",
        root / "usr/share/icons/hicolor/256x256/apps/cardpeek-ng.png",
    )


def build_deb(args):
    require("dpkg-deb")
    architecture = linux_architecture(args, "deb")
    work = ROOT / "target/packaging/deb"
    root = work / "root"
    reset_directory(root)
    linux_payload(args, root)
    notices = work / "THIRD_PARTY_NOTICES.md"
    generate_notices(notices)
    copy_legal(root / "usr/share/doc/cardpeek-ng", notices)
    installed_size = sum(path.stat().st_size for path in root.rglob("*") if path.is_file()) // 1024 + 1
    control = f"""Package: {PACKAGE}
Version: {VERSION}
Section: utils
Priority: optional
Architecture: {architecture}
Maintainer: Cardpeek-ng contributors
Homepage: {URL}
Depends: libgcc-s1, libpcsclite1, libxcb1, libxkbcommon0, libxkbcommon-x11-0
Recommends: pcscd
Installed-Size: {installed_size}
Description: Smart card inspection and analysis
 Cardpeek-ng reads smart cards through PC/SC readers and decodes their data
 with Lua analysers. It includes a desktop application, a command-line tool,
 and trace recording and replay support.
"""
    copy = root / "DEBIAN/control"
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(control, encoding="utf-8")
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / f"{PACKAGE}_{VERSION}_{architecture}.deb"
    if destination.exists():
        destination.unlink()
    run(
        "dpkg-deb",
        "--root-owner-group",
        "--build",
        root,
        destination,
    )
    return destination


def build_rpm(args):
    require("rpmbuild")
    architecture = linux_architecture(args, "rpm")
    work = ROOT / "target/packaging/rpm"
    root = work / "root"
    reset_directory(work)
    root.mkdir(parents=True)
    linux_payload(args, root)
    notices = work / "THIRD_PARTY_NOTICES.md"
    generate_notices(notices)
    for name in ("NOTICE.md", "THIRD_PARTY_NOTICES.md"):
        copy_file(notices if name == "THIRD_PARTY_NOTICES.md" else ROOT / name, root / "usr/share/doc/cardpeek-ng" / name)
    copy_file(ROOT / "LICENSE", root / "usr/share/licenses/cardpeek-ng/LICENSE")
    spec = f"""Name: {PACKAGE}
Version: {VERSION}
Release: 1%{{?dist}}
Summary: Smart card inspection and analysis
License: GPL-3.0-or-later
URL: {URL}
BuildArch: {architecture}
Requires: pcsc-lite-libs
Recommends: pcsc-lite-ccid
AutoReqProv: yes
%global __strip /bin/true

%description
Cardpeek-ng reads smart cards through PC/SC readers and decodes their data
with Lua analysers. It includes a desktop application, a command-line tool,
and trace recording and replay support.

%install
mkdir -p %{{buildroot}}
cp -a {root}/. %{{buildroot}}/

%files
/usr/bin/cardpeek
/usr/bin/cardpeek-desktop
/usr/share/applications/cardpeek-ng.desktop
/usr/share/icons/hicolor/256x256/apps/cardpeek-ng.png
%doc /usr/share/doc/cardpeek-ng/NOTICE.md
%doc /usr/share/doc/cardpeek-ng/THIRD_PARTY_NOTICES.md
%license /usr/share/licenses/cardpeek-ng/LICENSE
"""
    (work / "cardpeek-ng.spec").write_text(spec, encoding="utf-8")
    run(
        "rpmbuild",
        "-bb",
        "--define",
        f"_topdir {work}",
        "--buildroot",
        work / "buildroot",
        work / "cardpeek-ng.spec",
    )
    packages = list((work / "RPMS").rglob("*.rpm"))
    if len(packages) != 1:
        raise SystemExit("RPM builder did not produce exactly one package")
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / f"{PACKAGE}-{VERSION}-1.{architecture}.rpm"
    shutil.copy2(packages[0], destination)
    return destination


def windows_architecture(args):
    machine = args.target.split("-")[0] if args.target else host_architecture()
    try:
        return {"x86_64": "x64", "aarch64": "arm64"}[machine]
    except KeyError as error:
        raise SystemExit(f"Unsupported Windows architecture: {machine}") from error


def rtf(source, destination):
    text = source.read_text(encoding="utf-8")
    escaped = text.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
    escaped = escaped.replace("\r", "").replace("\n", "\\par\n")
    destination.write_text("{\\rtf1\\ansi\\deff0\\fs20\n" + escaped + "}", encoding="ascii")


def build_msi(args):
    if sys.platform != "win32":
        raise SystemExit("MSI packages must be built on Windows with the WiX toolset")
    require("wix")
    architecture = windows_architecture(args)
    work = ROOT / "target/packaging/msi"
    payload = work / "payload"
    reset_directory(payload)
    paths = binaries(args, ".exe")
    copy_file(paths["desktop"], payload / "cardpeek-desktop.exe")
    copy_file(paths["cli"], payload / "cardpeek.exe")
    notices = work / "THIRD_PARTY_NOTICES.md"
    generate_notices(notices)
    copy_legal(payload, notices)
    rtf(ROOT / "LICENSE", work / "LICENSE.rtf")
    template = (ROOT / "packaging/windows/cardpeek-ng.wxs").read_text(encoding="utf-8")
    replacements = {
        "@VERSION@": VERSION,
        "@PAYLOAD@": str(payload),
        "@LICENSE_RTF@": str(work / "LICENSE.rtf"),
        "@ICON@": str(ROOT / "resources/icon.ico"),
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    source = work / "cardpeek-ng.wxs"
    source.write_text(template, encoding="utf-8")
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / f"{PRODUCT}-{VERSION}-{architecture}.msi"
    if destination.exists():
        destination.unlink()
    run(
        "wix",
        "build",
        "-arch",
        architecture,
        "-ext",
        "WixToolset.UI.wixext",
        "-out",
        destination,
        source,
    )
    return destination


def create_icns(destination):
    work = ROOT / "target/packaging/pkg/Cardpeek-ng.iconset"
    reset_directory(work)
    sizes = (16, 32, 128, 256, 512)
    for size in sizes:
        for scale in (1, 2):
            suffix = "@2x" if scale == 2 else ""
            output = work / f"icon_{size}x{size}{suffix}.png"
            run("sips", "-z", size * scale, size * scale, ROOT / "resources/icon.png", "--out", output,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("iconutil", "--convert", "icns", "--output", destination, work)


def codesign(identity, app):
    require("codesign")
    for executable in (app / "Contents/MacOS/cardpeek", app / "Contents/MacOS/cardpeek-desktop"):
        run("codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identity, executable)
    run("codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identity, app)
    run("codesign", "--verify", "--deep", "--strict", "--verbose=2", app)


def build_pkg(args):
    if sys.platform != "darwin":
        raise SystemExit("macOS packages must be built on macOS")
    for command in ("pkgbuild", "sips", "iconutil"):
        require(command)
    if args.target:
        machine = args.target.split("-")[0]
        if machine not in ("x86_64", "aarch64"):
            raise SystemExit(f"Unsupported macOS architecture: {machine}")
    architecture = args.target.split("-")[0] if args.target else host_architecture()
    work = ROOT / "target/packaging/pkg"
    root = work / "root"
    app = root / "Applications/Cardpeek-ng.app"
    reset_directory(root)
    paths = binaries(args)
    copy_file(paths["desktop"], app / "Contents/MacOS/cardpeek-desktop", executable=True)
    copy_file(paths["cli"], app / "Contents/MacOS/cardpeek", executable=True)
    notices = work / "THIRD_PARTY_NOTICES.md"
    generate_notices(notices)
    copy_legal(app / "Contents/Resources", notices)
    create_icns(app / "Contents/Resources/cardpeek-ng.icns")
    info = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": PRODUCT,
        "CFBundleExecutable": "cardpeek-desktop",
        "CFBundleIconFile": "cardpeek-ng",
        "CFBundleIdentifier": IDENTIFIER,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": PRODUCT,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
    }
    with (app / "Contents/Info.plist").open("wb") as output:
        plistlib.dump(info, output, sort_keys=True)
    cli_link = root / "usr/local/bin/cardpeek"
    cli_link.parent.mkdir(parents=True, exist_ok=True)
    cli_link.symlink_to("/Applications/Cardpeek-ng.app/Contents/MacOS/cardpeek")
    if args.codesign_identity:
        codesign(args.codesign_identity, app)
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / f"{PRODUCT}-{VERSION}-{architecture}.pkg"
    if destination.exists():
        destination.unlink()
    command = [
        "pkgbuild",
        "--root",
        root,
        "--identifier",
        IDENTIFIER,
        "--version",
        VERSION,
        "--install-location",
        "/",
    ]
    if args.installer_identity:
        command.extend(("--sign", args.installer_identity))
    command.append(destination)
    run(*command)
    if args.notary_profile:
        if not args.installer_identity:
            raise SystemExit("Notarization requires a signed installer package")
        run("xcrun", "notarytool", "submit", destination, "--keychain-profile", args.notary_profile, "--wait")
        run("xcrun", "stapler", "staple", destination)
    return destination


def parse_arguments():
    parser = argparse.ArgumentParser(description="Build native Cardpeek-ng install packages")
    parser.add_argument("format", choices=("deb", "rpm", "msi", "pkg"))
    parser.add_argument("--target", help="Rust target triple used for the existing or new binaries")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/packages")
    parser.add_argument("--no-build", action="store_true", help="Use existing release binaries")
    parser.add_argument("--codesign-identity", help="macOS Developer ID Application identity")
    parser.add_argument("--installer-identity", help="macOS Developer ID Installer identity")
    parser.add_argument("--notary-profile", help="macOS notarytool keychain profile")
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.format != "pkg" and (args.codesign_identity or args.installer_identity or args.notary_profile):
        parser.error("Signing and notarization options apply only to pkg builds")
    return args


def main():
    args = parse_arguments()
    build_binaries(args)
    builders = {"deb": build_deb, "rpm": build_rpm, "msi": build_msi, "pkg": build_pkg}
    destination = builders[args.format](args)
    print(f"Created {destination}")


if __name__ == "__main__":
    main()
