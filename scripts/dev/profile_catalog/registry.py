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


BROWSERS = ("Chrome", "Edge", "Brave", "Firefox", "Opera", "Safari")
PLATFORMS = ("Windows", "Macos", "Linux", "Android", "Ios")


def constructor(entry):
    """Derive the public name from a structurally checked catalog identity."""
    metadata = entry["metadata"]
    major = metadata["identity"]["build"].split(".", 1)[0]
    return f"v{major}_{metadata['platform'].lower()}"


def capture_prefix(path):
    """Read a bounded metadata prefix without loading the capture payload."""
    try:
        with path.open("rb") as capture:
            prefix = capture.read(8193)
    except OSError as error:
        raise DeclarationError("cannot read retained capture metadata") from error
    if len(prefix) > 8192:
        prefix = prefix[:8192].rpartition(b"\n")[0]
    return prefix


def capture_build(path):
    """Read one recorded build within a bounded fixture prefix."""
    versions = []
    prefix = capture_prefix(path)
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


def validate_identity(metadata, identifier, target):
    """Keep browser observations separate from pinned external presets."""
    keys(metadata, ("browser", "platform", "identity", "revision"), identifier)
    browser = choice(metadata["browser"], BROWSERS, "browser")
    platform = choice(metadata["platform"], PLATFORMS, "platform")
    revision = metadata["revision"]
    if type(revision) is not int or not 1 <= revision <= 0xFFFFFFFF:
        raise DeclarationError(f"{identifier}: invalid recipe revision")
    identity = metadata["identity"]
    if not isinstance(identity, dict):
        raise DeclarationError(f"{identifier}: invalid profile identity")
    kind = choice(identity.get("kind"), ("Observed", "Peer"), "profile identity")
    if kind == "Observed":
        keys(
            identity,
            ("kind", "build", "platform_release", "architecture", "environment"),
            "observed identity",
        )
        build = text(identity["build"], "browser build")
        if not re.fullmatch(r"[1-9][0-9]{0,5}(?:\.[0-9]+)+", build):
            raise DeclarationError(f"{identifier}: invalid browser build")
        expected_target = browser + platform + build.split(".", 1)[0]
        text(identity["platform_release"], "platform release")
        if identity["architecture"] is not None:
            choice(identity["architecture"], ("x86_64", "arm64"), "architecture")
        environment = choice(
            identity["environment"],
            ("Desktop", "Emulator", "PhysicalDevice"),
            "environment",
        )
        if (platform in ("Windows", "Macos", "Linux")) != (environment == "Desktop"):
            raise DeclarationError(f"{identifier}: incompatible capture environment")
        expected_id = (
            f"{browser.lower()}/{build}/{identity['platform_release']}/r{revision}"
        )
    else:
        keys(
            identity,
            ("kind", "project", "source_revision", "recipe", "release"),
            "peer identity",
        )
        for field in ("project", "recipe"):
            value = text(identity[field], f"peer {field}")
            if len(value) > 64 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
                raise DeclarationError(f"{identifier}: invalid peer {field}")
        if not isinstance(identity["source_revision"], str) or not re.fullmatch(
            r"[0-9a-f]{40}", identity["source_revision"]
        ):
            raise DeclarationError(
                f"{identifier}: peer source revision must be a full commit"
            )
        release = text(identity["release"], "peer advertised release")
        if not re.fullmatch(r"[1-9][0-9]{0,5}(?:\.[0-9]+)+", release):
            raise DeclarationError(f"{identifier}: invalid peer advertised release")
        expected_target = "Peer" + "".join(
            word[:1].upper() + word[1:]
            for field in ("project", "recipe")
            for word in identity[field].split("-")
        )
        expected_id = f"peer/{identity['project']}/{identity['recipe']}/r{revision}"
    if target != expected_target:
        raise DeclarationError(f"{identifier}: incompatible recipe target")
    if identifier != expected_id:
        raise DeclarationError(f"{identifier}: identifier disagrees with metadata")


def validate_peer_capture(path, identity):
    """Require retained execution metadata to name the exact external preset."""
    prefix = capture_prefix(path)
    if [line for line in prefix.splitlines() if line.startswith(b"format=")] != [
        b"format=phantom-peer-capture-v1"
    ] or not any(line.startswith(b"client_version=") for line in prefix.splitlines()):
        raise DeclarationError(
            "peer capture requires execution format and client version"
        )
    for field in ("project", "source_revision", "recipe"):
        key = f"peer_{field}".encode("ascii")
        values = [
            line.partition(b"=")[2]
            for line in prefix.splitlines()
            if line.partition(b"=")[0] == key
        ]
        if values != [identity[field].encode("ascii")]:
            raise DeclarationError(f"peer capture {field} disagrees with identity")


def validate(document, repo=REPO):
    check_depth(document)
    keys(document, ("schema", "profiles"), "catalog")
    if type(document["schema"]) is not int or document["schema"] != 2:
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
        target = text(entry["target"], "recipe target")
        validate_identity(metadata, identifier, target)
        browser = metadata["browser"]
        identity = metadata["identity"]
        peer = identity["kind"] == "Peer"
        if target in targets:
            raise DeclarationError(f"{identifier}: duplicate recipe target")
        targets.add(target)

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
                not peer and browser == "Firefox" and name == "ClientHints"
            ):
                raise DeclarationError(f"{identifier}: unsupported absence claim")
            references = layer["references"]
            if not isinstance(references, list) or len(references) > MAX_REFERENCES:
                raise DeclarationError(f"{identifier}: too many evidence references")
            if support == "Configured" and not references:
                raise DeclarationError(
                    f"{identifier}: configured layer lacks provenance"
                )
            if (
                peer
                and support == "Configured"
                and not any(
                    reference.get("kind") == "ExternalSource"
                    for reference in references
                    if isinstance(reference, dict)
                )
            ):
                raise DeclarationError(
                    f"{identifier}: peer layer lacks pinned external source"
                )
            for reference in references:
                keys(reference, ("kind", "location", "build"), "evidence reference")
                kind = choice(
                    reference["kind"],
                    (
                        "Capture",
                        "Source",
                        "Reused",
                        "Recipe",
                        "ExternalSource",
                        "PeerCapture",
                    ),
                    "evidence kind",
                )
                if (peer and kind in ("Source", "Capture")) or (
                    not peer and kind in ("ExternalSource", "PeerCapture")
                ):
                    raise DeclarationError(
                        "evidence kind disagrees with profile identity"
                    )
                location = text(reference["location"], "evidence location")
                text(reference["build"], "evidence build")
                if location.startswith("https://"):
                    if kind not in ("Source", "ExternalSource"):
                        raise DeclarationError("only source references may use URLs")
                    try:
                        url = urlsplit(location)
                    except ValueError as error:
                        raise DeclarationError("invalid primary-source URL") from error
                    if not url.hostname or url.username or url.password:
                        raise DeclarationError("invalid primary-source URL")
                    if kind == "ExternalSource" and (
                        f"/{identity['source_revision']}/" not in url.path
                    ):
                        raise DeclarationError(
                            "external source URL must pin the peer commit"
                        )
                else:
                    if kind in ("Source", "ExternalSource"):
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
                        kind in ("Capture", "PeerCapture")
                        and capture_build(repo / path) != reference["build"]
                    ):
                        raise DeclarationError(
                            "capture reference build disagrees with retained metadata"
                        )
                    if kind == "PeerCapture":
                        if not location.startswith(
                            "crates/phantom-profile/tests/fixtures/peers/"
                        ):
                            raise DeclarationError(
                                "peer capture must name a retained peer fixture"
                            )
                        validate_peer_capture(repo / path, identity)
            string_list(layer["verified_fields"], "verified fields")
            string_list(layer["limitations"], "limitations")
            if layer["verified_fields"] and not any(
                item["kind"] in ("Capture", "PeerCapture") for item in references
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
        "    ProfileDefinition, ProfileId, ProfileIdentity, ProfileLayer, ProfileMetadata, ProfilePlatform,",
        "    RequestTemplateBinding, RequestTemplateKind, connection_profile_definitions,",
        "    request_template_definitions,",
        "};",
        "",
        "#[rustfmt::skip]",
        "pub(super) static PROFILES: &[ProfileDefinition] = &[",
    ]
    for entry in profiles:
        metadata = entry["metadata"]
        identity = metadata["identity"]
        if identity["kind"] == "Observed":
            architecture = (
                "None"
                if identity["architecture"] is None
                else f"Some({rust_string(identity['architecture'])})"
            )
            identity_lines = [
                "            identity: ProfileIdentity::Observed {",
                f"                build: {rust_string(identity['build'])},",
                f"                platform_release: {rust_string(identity['platform_release'])},",
                f"                architecture: {architecture},",
                f"                environment: CaptureEnvironment::{identity['environment']},",
            ]
        else:
            identity_lines = [
                "            identity: ProfileIdentity::Peer {",
                *[
                    f"                {field}: {rust_string(identity[field])},"
                    for field in ("project", "source_revision", "recipe", "release")
                ],
            ]
        lines.extend(
            [
                "    ProfileDefinition {",
                f"        id: ProfileId({rust_string(entry['id'])}),",
                f"        selector: {rust_string(entry['selector'])},",
                "        metadata: ProfileMetadata {",
                f"            browser: Browser::{metadata['browser']},",
                f"            platform: ProfilePlatform::{metadata['platform']},",
                *identity_lines,
                "            },",
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
        if not any(
            entry["metadata"]["browser"] == browser
            and entry["metadata"]["identity"]["kind"] == "Observed"
            for entry in profiles
        ):
            continue
        lines.extend([f"pub(crate) mod {browser.lower()} {{"])
        for entry in sorted(profiles, key=lambda item: item["target"]):
            metadata = entry["metadata"]
            if (
                metadata["browser"] != browser
                or metadata["identity"]["kind"] != "Observed"
            ):
                continue
            identity = metadata["identity"]
            lines.extend(
                [
                    f"    /// Returns the {browser} {identity['build']} profile for {identity['platform_release']}.",
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
