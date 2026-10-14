"""Validate catalog records and generate the committed Rust registry offline."""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
RECORDS = REPO / "crates/phantom-profile/catalog/profiles.json"
OUTPUT = REPO / "crates/phantom-profile/src/catalog/generated.rs"

# Resource ceilings for local declarations, not corpus performance claims.
MAX_BYTES = 16 * 1024 * 1024
MAX_PROFILES = 4096
MAX_DEPTH = 16
MAX_STRING = 4096
MAX_REFERENCES = 16
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
BINDINGS = {
    "ChromeWindows154": ("Chrome", "Windows", WINDOWS),
    "ChromeAndroid154": ("Chrome", "Android", ANDROID),
    "EdgeWindows154": ("Edge", "Windows", WINDOWS),
    "EdgeAndroid153": ("Edge", "Android", ANDROID - {"WebSocket"}),
    "BraveWindows154": ("Brave", "Windows", WINDOWS),
    "BraveAndroid153": ("Brave", "Android", ANDROID),
    "FirefoxWindows157": ("Firefox", "Windows", WINDOWS - {"Udp", "ClientHints"}),
    "FirefoxAndroid156": ("Firefox", "Android", {"TcpTls"}),
    "OperaWindows136": ("Opera", "Windows", WINDOWS),
    "OperaAndroid102": ("Opera", "Android", {"TcpTls", "ClientHints"}),
}
TARGETS = {
    "ChromeWindows154": ("154.0.8037.97", "windows-11-26200", None, "Desktop", 1),
    "ChromeAndroid154": (
        "154.0.8037.57",
        "android-17-pixel7-emulator",
        "x86_64",
        "Emulator",
        1,
    ),
    "EdgeWindows154": ("154.0.4258.48", "windows-11-26200", None, "Desktop", 1),
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


class DeclarationError(ValueError):
    """A declaration violates the closed schema or compiled recipe contract."""


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeclarationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def keys(value, expected, context):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise DeclarationError(f"{context}: expected keys {', '.join(expected)}")


def text(value, context):
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise DeclarationError(f"{context}: expected bounded nonempty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DeclarationError(f"{context}: control characters are forbidden")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise DeclarationError(f"{context}: invalid Unicode scalar value")
    return value


def choice(value, allowed, context):
    text(value, context)
    if value not in allowed:
        raise DeclarationError(f"{context}: unknown value {value}")
    return value


def string_list(value, context):
    if not isinstance(value, list) or len(value) > 64:
        raise DeclarationError(f"{context}: expected at most 64 strings")
    for item in value:
        text(item, context)
    if len(set(value)) != len(value):
        raise DeclarationError(f"{context}: duplicate entry")


def check_depth(value, depth=0):
    if depth > MAX_DEPTH:
        raise DeclarationError("declaration nesting limit exceeded")
    if isinstance(value, dict):
        for item in value.values():
            check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_depth(item, depth + 1)


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
        keys(entry, ("id", "binding", "metadata", "layers"), "profile")
        identifier = text(entry["id"], "profile id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9./-]{0,191}", identifier):
            raise DeclarationError("invalid profile identifier")
        if identifier in ids:
            raise DeclarationError(f"duplicate profile identifier: {identifier}")
        ids.add(identifier)
        binding = choice(entry["binding"], BINDINGS, identifier)
        browser, platform, configured = BINDINGS[binding]

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
            raise DeclarationError(f"{identifier}: incompatible recipe binding")
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
        target = tuple(
            metadata[key]
            for key in (
                "build",
                "platform_release",
                "architecture",
                "environment",
                "revision",
            )
        )
        if target != TARGETS[binding]:
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
                    f"{identifier}: support disagrees with {binding} for {name}"
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
    return sorted(profiles, key=lambda entry: entry["id"])


def load(path=RECORDS, repo=REPO):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise DeclarationError("catalog input byte limit exceeded")
    try:
        document = json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise DeclarationError(f"invalid catalog JSON: {error}") from error
    return validate(document, repo)


def rust_string(value):
    # JSON escaping of printable ASCII matches ordinary Rust string literals.
    # Keep non-ASCII literal so JSON's \uXXXX syntax never reaches Rust.
    return json.dumps(value, ensure_ascii=False)


def rust_strings(values):
    return "&[" + ", ".join(rust_string(value) for value in values) + "]"


def generate(profiles):
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/profiles.json.",
        "use super::{",
        "    Browser, CaptureEnvironment, EvidenceKind, EvidenceReference, LayerEvidence, LayerSupport,",
        "    ProfileDefinition, ProfileId, ProfileLayer, ProfileMetadata, ProfilePlatform, RecipeBinding,",
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
                f"        binding: RecipeBinding::{entry['binding']},",
                "    },",
            ]
        )
    lines.extend(["];"])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="reject a stale committed registry"
    )
    arguments = parser.parse_args()
    try:
        generated = generate(load())
        if arguments.check:
            if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != generated:
                raise DeclarationError(
                    "catalog registry is stale; run generate_profiles.py"
                )
        else:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    except (DeclarationError, OSError) as error:
        print(f"catalog generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
