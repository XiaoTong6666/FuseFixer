#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


APK_SIGNATURE_FILES = (
    "META-INF/MANIFEST.MF",
    ".SF",
    ".RSA",
    ".DSA",
    ".EC",
)
SCRIPT_NAMES = {
    "customize.sh",
    "post-fs-data.sh",
    "service.sh",
    "uninstall.sh",
    "verify.sh",
    "util_functions.sh",
    "META-INF/com/google/android/update-binary",
}


def workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent


def run_cmd(args: list[str], fail_msg: str) -> None:
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        output = proc.stdout.strip()
        raise RuntimeError(f"{fail_msg}\nCommand: {' '.join(args)}\n{output}")


def version_key(version: str) -> tuple[int, ...]:
    parts = []
    for token in version.replace("-", ".").split("."):
        if token.isdigit():
            parts.append(int(token))
    return tuple(parts) if parts else (0,)


def read_local_properties() -> dict[str, str]:
    path = workspace_root() / "local.properties"
    if not path.exists():
        return {}

    props: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        props[key.strip()] = value.strip()
    return props


def find_android_tool(tool_base_name: str, sdk_root: Optional[Path]) -> Optional[Path]:
    direct = shutil.which(tool_base_name)
    if direct:
        return Path(direct)

    if sdk_root is None:
        return None

    build_tools = sdk_root / "build-tools"
    if not build_tools.exists():
        return None

    executable_names = [tool_base_name]
    if os.name == "nt":
        executable_names = [f"{tool_base_name}.exe", f"{tool_base_name}.bat", tool_base_name]

    candidates: list[tuple[tuple[int, ...], Path]] = []
    for version_dir in build_tools.iterdir():
        if not version_dir.is_dir():
            continue
        for name in executable_names:
            candidate = version_dir / name
            if candidate.exists():
                candidates.append((version_key(version_dir.name), candidate))

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def resolve_sdk_root(local_properties: dict[str, str]) -> Optional[Path]:
    sdk_dir = local_properties.get("sdk.dir")
    if sdk_dir:
        return Path(sdk_dir)

    env_sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if env_sdk:
        return Path(env_sdk)
    return None


def resolve_signing(local_properties: dict[str, str]) -> Optional[dict[str, str]]:
    candidates: list[Path] = []
    configured = local_properties.get("ANDROID_DEBUG_KEYSTORE")
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path.home() / ".android" / "debug.keystore")

    for candidate in candidates:
        if candidate.exists():
            return {
                "keystore_path": str(candidate.resolve()),
                "key_alias": "androiddebugkey",
                "keystore_pass": "android",
                "key_pass": "android",
            }
    return None


def metadata_path(build_type: str) -> Path:
    return workspace_root() / "app" / "build" / "outputs" / "apk" / build_type / "output-metadata.json"


def load_output_metadata(build_type: str) -> dict:
    path = metadata_path(build_type)
    if not path.exists():
        raise FileNotFoundError(f"Missing APK metadata: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def locate_apk(build_type: str) -> tuple[Path, str, int]:
    metadata = load_output_metadata(build_type)
    elements = metadata.get("elements") or []
    if not elements:
        raise RuntimeError(f"No APK elements found in {metadata_path(build_type)}")
    element = elements[0]

    apk_dir = workspace_root() / "app" / "build" / "outputs" / "apk" / build_type
    output_file = element.get("outputFile") or "app-debug.apk"
    apk_path = apk_dir / output_file
    if not apk_path.exists():
        fallback = apk_dir / f"app-{build_type}.apk"
        apk_path = fallback if fallback.exists() else apk_path
    if not apk_path.exists():
        raise FileNotFoundError(f"Debug APK not found under {apk_dir}")

    version_name = str(element.get("versionName") or metadata.get("versionName") or "1.0")
    version_code = int(element.get("versionCode") or metadata.get("versionCode") or 1)
    return apk_path, version_name, version_code


def is_signature_entry(name: str) -> bool:
    return name == APK_SIGNATURE_FILES[0] or any(name.startswith("META-INF/") and name.endswith(ext) for ext in APK_SIGNATURE_FILES[1:])


def copy_zip_entry(zin: ZipFile, zout: ZipFile, info: ZipInfo) -> bytes:
    data = zin.read(info.filename)
    new_info = ZipInfo(filename=info.filename, date_time=info.date_time)
    new_info.compress_type = info.compress_type
    new_info.external_attr = info.external_attr
    new_info.comment = info.comment
    new_info.create_system = info.create_system
    new_info.extra = info.extra
    if info.compress_type == ZIP_DEFLATED:
        zout.writestr(new_info, data, compress_type=ZIP_DEFLATED)
    else:
        zout.writestr(new_info, data)
    return data


def template_dir() -> Path:
    return workspace_root() / "template" / "module"


def template_files() -> list[Path]:
    root = template_dir()
    if not root.exists():
        raise FileNotFoundError(f"Missing module template directory: {root}")
    return sorted([path for path in root.rglob("*") if path.is_file()])


def template_entry_names() -> set[str]:
    return {path.relative_to(template_dir()).as_posix() for path in template_files()}


def is_generated_module_entry(name: str, template_entries: set[str]) -> bool:
    return (
        name in template_entries
        or name.startswith("dex/")
        or name.startswith("framework/")
        or name.startswith("zygisk/")
    )


def render_template(
    relative_path: str,
    version_name: str,
    version_code: int,
    commit_hash: str,
    build_type: str,
) -> bytes:
    source = template_dir() / relative_path
    text = source.read_text(encoding="utf-8")
    if relative_path == "module.prop":
        text = text.replace("@VERSION_NAME@", version_name)
        text = text.replace("@VERSION_CODE@", str(version_code))
        text = text.replace("@COMMIT_HASH@", commit_hash)
        text = text.replace("@BUILD_TYPE@", build_type)
    return text.encode("utf-8")


def file_mode_for(relative_path: str) -> int:
    return 0o100755 if relative_path in SCRIPT_NAMES else 0o100644


def add_bytes_entry(zout: ZipFile, relative_path: str, data: bytes, compress_type: int = ZIP_DEFLATED) -> None:
    info = ZipInfo(relative_path)
    info.compress_type = compress_type
    info.create_system = 3
    info.external_attr = file_mode_for(relative_path) << 16
    zout.writestr(info, data, compress_type=compress_type)


def package_module(
    apk_path: Path,
    unsigned_path: Path,
    version_name: str,
    version_code: int,
    commit_hash: str,
    build_type: str,
) -> None:
    template_entries = template_entry_names()

    with ZipFile(apk_path, "r") as zin, ZipFile(unsigned_path, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if is_signature_entry(name) or is_generated_module_entry(name, template_entries):
                continue

            copy_zip_entry(zin, zout, info)

        for file_path in template_files():
            relative_path = file_path.relative_to(template_dir()).as_posix()
            add_bytes_entry(
                zout,
                relative_path,
                render_template(relative_path, version_name, version_code, commit_hash, build_type),
            )


def validate_module_archive(archive_path: Path) -> None:
    with ZipFile(archive_path, "r") as archive:
        names = set(archive.namelist())

    missing = sorted(template_entry_names() - names)
    if "classes.dex" not in names:
        missing.append("classes.dex")
    if not any(
        name.startswith("lib/") and name.endswith("/libzygisk.so") for name in names
    ):
        missing.append("lib/<abi>/libzygisk.so")
    if not any(
        name.startswith("lib/") and name.endswith("/libfusehide.so") for name in names
    ):
        missing.append("lib/<abi>/libfusehide.so")
    if missing:
        raise RuntimeError(
            f"Module archive is incomplete: {archive_path}\nMissing: {', '.join(missing)}"
        )


def zipalign_and_sign(unsigned_path: Path, final_path: Path, sdk_root: Optional[Path], signing: Optional[dict[str, str]]) -> None:
    zipalign = find_android_tool("zipalign", sdk_root)
    if zipalign is None:
        raise FileNotFoundError("zipalign not found in PATH or Android SDK build-tools")

    aligned_path = final_path.with_name(final_path.stem + "-aligned.zip")
    if aligned_path.exists():
        aligned_path.unlink()

    run_cmd([str(zipalign), "-P", "16", "-f", "4", str(unsigned_path), str(aligned_path)], "zipalign failed")

    try:
        if signing is None:
            raise RuntimeError("APK signing configuration is required for module archives")

        apksigner = find_android_tool("apksigner", sdk_root)
        if apksigner is None:
            raise FileNotFoundError("apksigner not found in PATH or Android SDK build-tools")

        run_cmd(
            [
                str(apksigner),
                "sign",
                "--v1-signing-enabled",
                "false",
                "--v2-signing-enabled",
                "true",
                "--v3-signing-enabled",
                "false",
                "--v4-signing-enabled",
                "false",
                "--min-sdk-version",
                "31",
                "--ks",
                signing["keystore_path"],
                "--ks-key-alias",
                signing["key_alias"],
                "--ks-pass",
                f"pass:{signing['keystore_pass']}",
                "--key-pass",
                f"pass:{signing['key_pass']}",
                "--out",
                str(final_path),
                str(aligned_path),
            ],
            "apksigner failed",
        )
        run_cmd(
            [str(apksigner), "verify", "--verbose", str(final_path)],
            "apksigner verification failed",
        )
    finally:
        if aligned_path.exists():
            aligned_path.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Package the FuseHide APK into a Zygisk module zip while preserving APK contents."
    )
    parser.add_argument("--build-type", default="debug", help="APK build type to package, default: debug")
    parser.add_argument("--skip-build", action="store_true", help="Skip running :app:assemble<BuildType>")
    parser.add_argument("--out-dir", help="Output directory, default: app/build/zygisk")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Replace the Gradle APK with the signed module-ready archive",
    )
    return parser


def gradle_task_name(build_type: str) -> str:
    return f":app:assemble{build_type[:1].upper()}{build_type[1:]}"


def git_commit_hash() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=workspace_root(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def main() -> int:
    os.chdir(workspace_root())
    args = build_parser().parse_args()

    local_properties = read_local_properties()
    sdk_root = resolve_sdk_root(local_properties)
    signing = resolve_signing(local_properties)
    if args.in_place and signing is None:
        raise RuntimeError(
            "In-place APK repacking requires ANDROID_DEBUG_KEYSTORE or ~/.android/debug.keystore"
        )

    if not args.skip_build:
        run_cmd([str(workspace_root() / "gradlew"), gradle_task_name(args.build_type)], "Gradle build failed")

    apk_path, version_name, version_code = locate_apk(args.build_type)
    commit_hash = git_commit_hash()
    build_metadata = f"{version_code}-{commit_hash}-{args.build_type}"
    out_dir = Path(args.out_dir).resolve() if args.out_dir else workspace_root() / "app" / "build" / "zygisk"
    out_dir.mkdir(parents=True, exist_ok=True)

    unsigned_path = out_dir / f"FuseHide-{version_name}_{build_metadata}-unsigned.zip"
    final_path = out_dir / f"FuseHide-{version_name}_{build_metadata}.zip"
    for stale in (unsigned_path, final_path):
        if stale.exists():
            stale.unlink()

    try:
        package_module(
            apk_path,
            unsigned_path,
            version_name,
            version_code,
            commit_hash,
            args.build_type,
        )
        zipalign_and_sign(unsigned_path, final_path, sdk_root, signing)
        validate_module_archive(final_path)
        if args.in_place:
            shutil.copy2(final_path, apk_path)
            validate_module_archive(apk_path)
    finally:
        if unsigned_path.exists():
            unsigned_path.unlink()

    print(f"Input APK : {apk_path}")
    print(f"Output    : {final_path}")
    if args.in_place:
        print(f"Updated   : {apk_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
