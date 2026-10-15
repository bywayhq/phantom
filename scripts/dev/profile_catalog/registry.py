"""Exact catalog metadata, evidence and current compiled targets."""

import re
from pathlib import Path
from urllib.parse import urlsplit

from .composition import validate_composition
from .declarations import (
    MAX_PROFILES,
    MAX_REFERENCES,
    REPO,
    DeclarationError,
    check_depth,
    choice,
    component_identifier,
    keys,
    string_list,
    text,
)
from .request_template import REQUEST_KINDS
from .rust_literals import (
    rust_string,
    rust_strings,
)

LAYERS = (
    "TcpTls",
    "Tcp",
    "Udp",
    "Dns",
    "Http1",
    "Http2",
    "QuicTls",
    "QuicTransport",
    "Http3",
    "Http3Request",
    "ClientHints",
    "WebSocket",
    "ProxyConnect",
    "CookiePlacement",
)


WINDOWS = set(LAYERS)


ANDROID = {
    "TcpTls",
    "Http2",
    "QuicTls",
    "QuicTransport",
    "Http3",
    "Http3Request",
    "ClientHints",
    "WebSocket",
}


TARGET_CONTRACTS = {
    "ChromeWindows154": ("Chrome", "Windows", WINDOWS),
    "ChromeAndroid154": ("Chrome", "Android", ANDROID | {"Tcp"}),
    "EdgeWindows154": ("Edge", "Windows", WINDOWS),
    "EdgeWindows153": (
        "Edge",
        "Windows",
        {
            "TcpTls",
            "Http2",
            "QuicTls",
            "QuicTransport",
            "Http3",
            "Http3Request",
            "ClientHints",
        },
    ),
    "EdgeAndroid153": ("Edge", "Android", ANDROID),
    "BraveWindows154": ("Brave", "Windows", WINDOWS),
    "BraveAndroid153": ("Brave", "Android", ANDROID),
    "FirefoxWindows157": ("Firefox", "Windows", WINDOWS - {"Udp", "ClientHints"}),
    "FirefoxAndroid156": ("Firefox", "Android", {"TcpTls", "Tcp"}),
    "OperaWindows136": ("Opera", "Windows", WINDOWS),
    "OperaAndroid102": ("Opera", "Android", {"TcpTls", "ClientHints"}),
}


TARGET_METADATA = {
    "ChromeWindows154": ("154.0.8037.97", "windows-11-26200", None, "Desktop", 1),
    "ChromeAndroid154": (
        "154.0.8037.57",
        "android-17-pixel7-emulator",
        "x86_64",
        "Emulator",
        1,
    ),
    "EdgeWindows154": ("154.0.4258.48", "windows-11-26200", None, "Desktop", 1),
    "EdgeWindows153": ("153.0.4234.48", "windows-11-26200", None, "Desktop", 1),
    "EdgeAndroid153": (
        "153.0.4234.49",
        "android-17-pixel7-emulator",
        "arm64",
        "Emulator",
        1,
    ),
    "BraveWindows154": ("154.1.96.59", "windows-11-26200", None, "Desktop", 1),
    "BraveAndroid153": (
        "153.1.95.104",
        "android-17-pixel7-emulator",
        None,
        "Emulator",
        1,
    ),
    "FirefoxWindows157": ("157.0", "windows-11-26200", None, "Desktop", 1),
    "FirefoxAndroid156": ("156.0.1", "android-35-emulator", None, "Emulator", 1),
    "OperaWindows136": ("136.0.6008.52", "windows-11-26200", None, "Desktop", 1),
    "OperaAndroid102": (
        "102.1.5206.90382",
        "android-17-pixel7-emulator",
        None,
        "Emulator",
        1,
    ),
}


def capture_build(path):
    """Read one recorded build within a bounded fixture prefix."""
    try:
        with path.open("rb") as capture:
            prefix = capture.read(8193)
    except OSError as error:
        raise DeclarationError("cannot read retained capture metadata") from error
    if len(prefix) > 8192:
        prefix = prefix[:8192].rpartition(b"\n")[0]
    versions = []
    for line in prefix.splitlines():
        key, separator, value = line.partition(b"=")
        if separator and key in (b"browser_version", b"client_version"):
            try:
                versions.append(text(value.decode("ascii"), "capture build"))
            except UnicodeDecodeError as error:
                raise DeclarationError("capture build must be ASCII") from error
    if len(versions) != 1:
        raise DeclarationError("capture needs one retained build metadata field")
    return versions[0]


def validate(document, repo=REPO):
    check_depth(document)
    keys(document, ("schema", "profiles"), "catalog")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise DeclarationError("unsupported catalog schema")
    profiles = document["profiles"]
    if not isinstance(profiles, list) or not 0 < len(profiles) <= MAX_PROFILES:
        raise DeclarationError("profile count is outside declaration limits")

    ids = set()
    for entry in profiles:
        keys(
            entry,
            ("id", "target", "metadata", "layers", "templates", "composition"),
            "profile",
        )
        identifier = text(entry["id"], "profile id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9./-]{0,191}", identifier):
            raise DeclarationError("invalid profile identifier")
        if identifier in ids:
            raise DeclarationError(f"duplicate profile identifier: {identifier}")
        ids.add(identifier)
        target = choice(entry["target"], TARGET_CONTRACTS, identifier)
        browser, platform, configured = TARGET_CONTRACTS[target]
        templates = entry["templates"]
        if not isinstance(templates, dict) or not set(templates) <= set(REQUEST_KINDS):
            raise DeclarationError(
                "profile requires an explicit request-kind template map"
            )
        for template_id in templates.values():
            component_identifier(template_id)

        metadata = entry["metadata"]
        keys(
            metadata,
            (
                "browser",
                "build",
                "platform",
                "platform_release",
                "architecture",
                "environment",
                "revision",
            ),
            identifier,
        )
        if metadata["browser"] != browser or metadata["platform"] != platform:
            raise DeclarationError(f"{identifier}: incompatible recipe target")
        text(metadata["build"], "browser build")
        text(metadata["platform_release"], "platform release")
        if metadata["architecture"] is not None:
            choice(metadata["architecture"], ("x86_64", "arm64"), "architecture")
        environment = choice(
            metadata["environment"],
            ("Desktop", "Emulator", "PhysicalDevice"),
            "environment",
        )
        if (platform == "Windows") != (environment == "Desktop"):
            raise DeclarationError(f"{identifier}: incompatible capture environment")
        revision = metadata["revision"]
        if type(revision) is not int or not 1 <= revision <= 0xFFFFFFFF:
            raise DeclarationError(f"{identifier}: invalid recipe revision")
        metadata_target = tuple(
            metadata[key]
            for key in (
                "build",
                "platform_release",
                "architecture",
                "environment",
                "revision",
            )
        )
        if metadata_target != TARGET_METADATA[target]:
            raise DeclarationError(
                f"{identifier}: unsupported recipe target or revision"
            )
        suffix = f"/{metadata['build']}/{metadata['platform_release']}/r{revision}"
        if identifier != browser.lower() + suffix:
            raise DeclarationError(f"{identifier}: identifier disagrees with metadata")

        layers = entry["layers"]
        if not isinstance(layers, list) or len(layers) != len(LAYERS):
            raise DeclarationError(f"{identifier}: every layer needs an explicit state")
        seen = set()
        for layer in layers:
            keys(
                layer,
                ("layer", "support", "references", "verified_fields", "limitations"),
                identifier,
            )
            name = choice(layer["layer"], LAYERS, "layer")
            if name in seen:
                raise DeclarationError(f"{identifier}: duplicate layer {name}")
            seen.add(name)
            support = choice(
                layer["support"],
                ("Configured", "IntentionallyAbsent", "Unavailable"),
                name,
            )
            if (support == "Configured") != (name in configured):
                raise DeclarationError(
                    f"{identifier}: support disagrees with {target} for {name}"
                )
            if support == "IntentionallyAbsent" and not (
                browser == "Firefox" and name == "ClientHints"
            ):
                raise DeclarationError(f"{identifier}: unsupported absence claim")
            references = layer["references"]
            if not isinstance(references, list) or len(references) > MAX_REFERENCES:
                raise DeclarationError(f"{identifier}: too many evidence references")
            if support == "Configured" and not references:
                raise DeclarationError(
                    f"{identifier}: configured layer lacks provenance"
                )
            for reference in references:
                keys(reference, ("kind", "location", "build"), "evidence reference")
                kind = choice(
                    reference["kind"],
                    ("Capture", "Source", "Reused", "Recipe"),
                    "evidence kind",
                )
                location = text(reference["location"], "evidence location")
                text(reference["build"], "evidence build")
                if location.startswith("https://"):
                    if kind != "Source":
                        raise DeclarationError("only source references may use URLs")
                    try:
                        url = urlsplit(location)
                    except ValueError as error:
                        raise DeclarationError("invalid primary-source URL") from error
                    if not url.hostname or url.username or url.password:
                        raise DeclarationError("invalid primary-source URL")
                else:
                    if kind == "Source":
                        raise DeclarationError(
                            "browser source must use an upstream HTTPS URL"
                        )
                    path = Path(location.split("#", 1)[0])
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in location
                        or ":" in location
                    ):
                        raise DeclarationError(
                            "evidence path must stay within the repository"
                        )
                    if not (repo / path).is_file():
                        raise DeclarationError(f"missing evidence file: {location}")
                    if not (repo / path).resolve().is_relative_to(repo.resolve()):
                        raise DeclarationError(
                            "evidence symlink escapes the repository"
                        )
                    if kind == "Capture" and not location.startswith("fixtures/"):
                        raise DeclarationError(
                            "capture reference must name a retained fixture"
                        )
                    if (
                        kind == "Capture"
                        and capture_build(repo / path) != reference["build"]
                    ):
                        raise DeclarationError(
                            "capture reference build disagrees with retained metadata"
                        )
            string_list(layer["verified_fields"], "verified fields")
            string_list(layer["limitations"], "limitations")
            if layer["verified_fields"] and not any(
                item["kind"] == "Capture" for item in references
            ):
                raise DeclarationError("observed fields require capture evidence")
            if support != "Configured" and layer["verified_fields"]:
                raise DeclarationError(
                    "unconfigured layer cannot claim verified settings"
                )
        validate_composition(entry)
    return sorted(profiles, key=lambda entry: entry["id"])


def generate(profiles):
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/profiles.json.",
        "use super::{",
        "    Browser, CaptureEnvironment, EvidenceKind, EvidenceReference, LayerEvidence, LayerSupport,",
        "    ProfileDefinition, ProfileId, ProfileLayer, ProfileMetadata, ProfilePlatform,",
        "    RequestTemplateBinding, RequestTemplateKind, connection_profile_definitions,",
        "    request_template_definitions,",
        "};",
        "",
        "#[rustfmt::skip]",
        "pub(super) static PROFILES: &[ProfileDefinition] = &[",
    ]
    for entry in profiles:
        metadata = entry["metadata"]
        architecture = (
            "None"
            if metadata["architecture"] is None
            else f"Some({rust_string(metadata['architecture'])})"
        )
        lines.extend(
            [
                "    ProfileDefinition {",
                f"        id: ProfileId({rust_string(entry['id'])}),",
                "        metadata: ProfileMetadata {",
                f"            browser: Browser::{metadata['browser']},",
                f"            build: {rust_string(metadata['build'])},",
                f"            platform: ProfilePlatform::{metadata['platform']},",
                f"            platform_release: {rust_string(metadata['platform_release'])},",
                f"            architecture: {architecture},",
                f"            environment: CaptureEnvironment::{metadata['environment']},",
                f"            revision: {metadata['revision']},",
                "        },",
                "        layers: &[",
            ]
        )
        by_layer = {layer["layer"]: layer for layer in entry["layers"]}
        for name in LAYERS:
            layer = by_layer[name]
            lines.extend(
                [
                    "            LayerEvidence {",
                    f"                layer: ProfileLayer::{name},",
                    f"                support: LayerSupport::{layer['support']},",
                    "                references: &[",
                ]
            )
            for reference in layer["references"]:
                lines.extend(
                    [
                        "                    EvidenceReference {",
                        f"                        kind: EvidenceKind::{reference['kind']},",
                        f"                        location: {rust_string(reference['location'])},",
                        f"                        build: {rust_string(reference['build'])},",
                        "                    },",
                    ]
                )
            lines.extend(
                [
                    "                ],",
                    f"                verified_fields: {rust_strings(layer['verified_fields'])},",
                    f"                limitations: {rust_strings(layer['limitations'])},",
                    "            },",
                ]
            )
        lines.extend(
            [
                "        ],",
                f"        composition: &connection_profile_definitions::{entry['target'].upper()},",
                "        templates: &[",
                *[
                    "            RequestTemplateBinding { "
                    f"kind: RequestTemplateKind::{kind}, "
                    f"definition: &request_template_definitions::{entry['templates'][kind].upper()} "
                    "},"
                    for kind in REQUEST_KINDS
                    if kind in entry["templates"]
                ],
                "        ],",
                "    },",
            ]
        )
    lines.extend(["];"])
    return "\n".join(lines) + "\n"
