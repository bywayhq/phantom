"""Catalog identity, evidence and generated browser entry points."""

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


BROWSERS = ("Chrome", "Edge", "Brave", "Firefox", "Opera")
PLATFORMS = ("Windows", "Macos", "Linux", "Android")


def constructor(entry):
    """Derive the public name from a structurally checked catalog identity."""
    metadata = entry["metadata"]
    major = metadata["build"].split(".", 1)[0]
    return f"v{major}_{metadata['platform'].lower()}"


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
    selectors = set()
    targets = set()
    validated = []
    for entry in profiles:
        keys(
            entry,
            (
                "id",
                "selector",
                "target",
                "metadata",
                "layers",
                "templates",
                "composition",
            ),
            "profile",
        )
        entry = dict(entry)
        identifier = text(entry["id"], "profile id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9./-]{0,191}", identifier):
            raise DeclarationError("invalid profile identifier")
        if identifier in ids:
            raise DeclarationError(f"duplicate profile identifier: {identifier}")
        if identifier in selectors:
            raise DeclarationError(
                f"profile identifier conflicts with selector: {identifier}"
            )
        ids.add(identifier)
        selector = text(entry["selector"], "profile selector")
        if selector in selectors:
            raise DeclarationError(f"duplicate profile selector: {selector}")
        if selector in ids:
            raise DeclarationError(
                f"profile selector conflicts with identifier: {selector}"
            )
        if len(selector) > 64 or not re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*", selector
        ):
            raise DeclarationError(f"{identifier}: invalid profile selector")
        selectors.add(selector)
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
        browser = choice(metadata["browser"], BROWSERS, "browser")
        platform = choice(metadata["platform"], PLATFORMS, "platform")
        build = text(metadata["build"], "browser build")
        if not re.fullmatch(r"[1-9][0-9]{0,5}(?:\.[0-9]+)+", build):
            raise DeclarationError(f"{identifier}: invalid browser build")
        target = text(entry["target"], "recipe target")
        if target != browser + platform + build.split(".", 1)[0]:
            raise DeclarationError(f"{identifier}: incompatible recipe target")
        if target in targets:
            raise DeclarationError(f"{identifier}: duplicate recipe target")
        targets.add(target)
        text(metadata["platform_release"], "platform release")
        if metadata["architecture"] is not None:
            choice(metadata["architecture"], ("x86_64", "arm64"), "architecture")
        environment = choice(
            metadata["environment"],
            ("Desktop", "Emulator", "PhysicalDevice"),
            "environment",
        )
        if (platform in ("Windows", "Macos", "Linux")) != (environment == "Desktop"):
            raise DeclarationError(f"{identifier}: incompatible capture environment")
        revision = metadata["revision"]
        if type(revision) is not int or not 1 <= revision <= 0xFFFFFFFF:
            raise DeclarationError(f"{identifier}: invalid recipe revision")
        suffix = f"/{metadata['build']}/{metadata['platform_release']}/r{revision}"
        if identifier != browser.lower() + suffix:
            raise DeclarationError(f"{identifier}: identifier disagrees with metadata")

        layers = entry["layers"]
        if not isinstance(layers, list) or len(layers) > len(LAYERS):
            raise DeclarationError(f"{identifier}: invalid evidence layers")
        expanded = []
        seen = set()
        for layer in layers:
            if not isinstance(layer, dict):
                raise DeclarationError(f"{identifier}: invalid layer evidence")
            optional = {"references", "verified_fields", "limitations"}
            keys(layer, {"layer", "support"} | (optional & layer.keys()), identifier)
            layer = {
                "references": [],
                "verified_fields": [],
                "limitations": [],
                **layer,
            }
            expanded.append(layer)
            name = choice(layer["layer"], LAYERS, "layer")
            if name in seen:
                raise DeclarationError(f"{identifier}: duplicate layer {name}")
            seen.add(name)
            support = choice(
                layer["support"],
                ("Configured", "IntentionallyAbsent", "Unavailable"),
                name,
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
        # An omitted evidence row cannot establish support for a component.
        entry["layers"] = expanded + [
            {
                "layer": name,
                "support": "Unavailable",
                "references": [],
                "verified_fields": [],
                "limitations": [],
            }
            for name in LAYERS
            if name not in seen
        ]
        validate_composition(entry)
        validated.append(entry)
    return sorted(validated, key=lambda entry: entry["id"])


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
                f"        selector: {rust_string(entry['selector'])},",
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


def generate_constructors(profiles):
    """Expose catalog compositions through the existing browser modules."""
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/profiles.json.",
        "",
    ]
    for browser in BROWSERS:
        lines.extend([f"pub(crate) mod {browser.lower()} {{"])
        for entry in sorted(profiles, key=lambda item: item["target"]):
            metadata = entry["metadata"]
            if metadata["browser"] != browser:
                continue
            lines.extend(
                [
                    f"    /// Returns the {browser} {metadata['build']} profile for {metadata['platform_release']}.",
                    "    ///",
                    "    /// Choose a request template separately. See the",
                    f"    /// [catalog evidence](crate::catalog::profile) for `{entry['id']}`",
                    "    /// for supplied layers, reused settings and capture limits.",
                    "    #[must_use]",
                    f"    pub fn {constructor(entry)}() -> crate::ClientProfile {{",
                    f"        crate::catalog::connection_profile_definitions::{entry['target'].upper()}.instantiate()",
                    "    }",
                    "",
                ]
            )
        if lines[-1] == "":
            lines.pop()
        lines.extend(["}", ""])
    return "\n".join(lines)
