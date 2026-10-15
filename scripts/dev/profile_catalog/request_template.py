"""Closed ordered template declarations and immutable compiled definitions."""

from .declarations import (
    MAX_COMPONENT_CHAIN,
    MAX_COMPONENTS,
    MAX_STRING,
    DeclarationError,
    boolean,
    bounded_integer,
    bounded_list,
    check_depth,
    choice,
    component_identifier,
    keys,
)
from .rust_literals import rust_option, rust_string

REQUEST_KINDS = ("Navigation", "FetchNoStore", "Fetch", "FetchUpload")
TEMPLATE_FIELDS = (
    "http1_fields",
    "http2_fields",
    "http3_fields",
    "http2_priority",
    "requested_client_hint_placement",
    "restarts_for_connection_accept_ch",
)
FIELD_KEYS = {
    "Literal": ("name", "value"),
    "Caller": ("name", "required"),
    "ClientHint": ("name",),
    "ClientHints": (),
    "ByTrust": ("name", "trustworthy", "untrustworthy"),
    "ByForwarding": ("name", "unforwarded", "forwarded"),
    "ProxyAuthorization": ("name", "attempt"),
    "RestartClientHints": (),
    "AltUsed": (),
}
HINT_FIELDS = {"ClientHint", "ClientHints"}
TOKEN_PUNCTUATION = "!#$%&'*+-.^_`|~"
GENERATED_FIELDS = {
    "host",
    "cookie",
    "content-length",
    "transfer-encoding",
    "trailer",
    "alt-used",
}
CONNECTION_FIELDS = {"connection", "keep-alive", "proxy-connection", "upgrade"}
MAX_FIELDS = 256


def validate_value(value):
    if not isinstance(value, str) or len(value) > MAX_STRING:
        raise DeclarationError("template value must be a bounded string")
    if any(char != "\t" and not " " <= char <= "~" for char in value):
        raise DeclarationError("template values require visible ASCII, spaces or tabs")


def validate_fields(fields, protocol):
    bounded_list(fields, 0, MAX_FIELDS, "template fields")
    names = set()
    attempts = set()
    hint_blocks = 0
    single_hints = 0
    restarts = 0
    for index, entry in enumerate(fields):
        if not isinstance(entry, dict) or "variant" not in entry:
            raise DeclarationError("template field requires a variant")
        variant = choice(entry["variant"], FIELD_KEYS, "template field variant")
        keys(entry, ("variant", *FIELD_KEYS[variant]), "template field")
        repeated_auth = False
        if variant == "AltUsed":
            if protocol != 3:
                raise DeclarationError("Alt-Used slots require HTTP/3")
        elif variant == "ProxyAuthorization":
            attempt = choice(
                entry["attempt"], ("Every", "Preemptive", "Replay"), "proxy attempt"
            )
            name = entry["name"]
            if not isinstance(name, str) or name.lower() != "proxy-authorization":
                raise DeclarationError("proxy slot must be named Proxy-Authorization")
            if protocol == 3:
                raise DeclarationError("HTTP/3 cannot carry a proxy authorization slot")
            if (
                attempt in attempts
                or "Every" in attempts
                or (attempt == "Every" and attempts)
            ):
                raise DeclarationError("proxy authorization attempts overlap")
            attempts.add(attempt)
            repeated_auth = len(attempts) > 1
        elif variant == "Literal":
            validate_value(entry["value"])
        elif variant in ("ByTrust", "ByForwarding"):
            pair = FIELD_KEYS[variant][1:]
            if all(entry[name] is None for name in pair):
                raise DeclarationError("conditional field requires at least one value")
            for name in pair:
                if entry[name] is not None:
                    validate_value(entry[name])
        elif variant == "Caller":
            boolean(entry["required"], "required caller field")
        elif variant == "ClientHint":
            single_hints += 1
        elif variant == "ClientHints":
            hint_blocks += 1
        elif variant == "RestartClientHints":
            restarts += 1

        if variant in HINT_FIELDS and not any(
            later["variant"] == "Literal"
            for later in fields[index + 1 :]
            if isinstance(later, dict) and "variant" in later
        ):
            raise DeclarationError("client-hint slots require a later literal field")
        if "name" not in entry and variant != "AltUsed":
            continue
        name = "alt-used" if variant == "AltUsed" else entry["name"]
        if not isinstance(name, str) or not name or len(name) > MAX_STRING:
            raise DeclarationError(
                "template field name must be a bounded nonempty token"
            )
        if any(
            not (
                "a" <= char <= "z"
                or "A" <= char <= "Z"
                or "0" <= char <= "9"
                or char in TOKEN_PUNCTUATION
            )
            for char in name
        ):
            raise DeclarationError("template field name must be an ASCII token")
        lower = name.lower()
        if (protocol != 1 or variant == "ClientHint") and lower != name:
            raise DeclarationError(
                "HTTP/2, HTTP/3 and client-hint names must be lowercase"
            )
        if protocol != 1 and (
            lower in CONNECTION_FIELDS
            or (
                lower == "te"
                and not (variant == "Literal" and entry["value"] == "trailers")
            )
        ):
            raise DeclarationError(
                "HTTP/2 and HTTP/3 cannot carry connection-specific fields"
            )
        if (
            lower in GENERATED_FIELDS
            and variant != "AltUsed"
            and not (lower == "content-length" and variant == "Caller")
        ):
            raise DeclarationError("template cannot declare client-generated fields")
        if lower in names and not repeated_auth:
            raise DeclarationError("template field names must not repeat")
        names.add(lower)
    if hint_blocks > 1 or (single_hints and not hint_blocks):
        raise DeclarationError(
            "individual hints require exactly one client-hints block"
        )
    if restarts > 1:
        raise DeclarationError("template cannot repeat its restart client-hints slot")


def following_names(fields, index, skip_hints=False):
    names = []
    for entry in fields[index + 1 :]:
        if entry["variant"] == "AltUsed":
            continue
        if skip_hints and entry["variant"] in HINT_FIELDS:
            continue
        if "name" in entry:
            names.append(entry["name"].lower())
        if entry["variant"] == "Literal":
            break
    return names


def hint_signature(fields):
    return [
        (entry.get("name"), following_names(fields, index, True))
        for index, entry in enumerate(fields)
        if entry["variant"] in HINT_FIELDS
    ]


def restart_signature(fields):
    for index, entry in enumerate(fields):
        if entry["variant"] == "RestartClientHints":
            return following_names(fields, index)
    return None


def validate_template_values(value):
    keys(value, TEMPLATE_FIELDS, "template values")
    for name in TEMPLATE_FIELDS[-2:]:
        boolean(value[name], name)
    priority = value["http2_priority"]
    if priority is not None:
        keys(
            priority,
            ("dependency_stream_id", "weight", "exclusive"),
            "template priority",
        )
        bounded_integer(priority["dependency_stream_id"], 0, 0, "template dependency")
        bounded_integer(priority["weight"], 1, 256, "template weight")
        boolean(priority["exclusive"], "template exclusive priority")
    validate_fields(value["http1_fields"], 1)
    validate_fields(value["http2_fields"], 2)
    lists = [value["http1_fields"], value["http2_fields"]]
    if value["http3_fields"] is not None:
        validate_fields(value["http3_fields"], 3)
        lists.append(value["http3_fields"])
    hints = hint_signature(value["http2_fields"])
    restart = restart_signature(value["http2_fields"])
    for fields in lists:
        if hint_signature(fields) != hints:
            raise DeclarationError(
                "client-hint slots and following fields disagree across protocols"
            )
        other = restart_signature(fields)
        if (restart is None) != (other is None):
            raise DeclarationError(
                "restart client-hint slots disagree across protocols"
            )
        if restart is not None and (
            bool(restart) != bool(other)
            or any(a != b for a, b in zip(restart, other, strict=False))
        ):
            raise DeclarationError(
                "restart client-hint following fields disagree across protocols"
            )


def validate_templates(document):
    check_depth(document)
    keys(document, ("schema", "templates"), "request templates")
    bounded_integer(document["schema"], 1, 1, "template schema")
    bounded_list(document["templates"], 1, MAX_COMPONENTS, "template declarations")
    entries = {}
    for entry in document["templates"]:
        keys(entry, ("id", "base", "values"), "template declaration")
        identifier = component_identifier(entry["id"])
        if identifier in entries:
            raise DeclarationError("duplicate template identifier")
        if entry["base"] is not None:
            component_identifier(entry["base"])
        if not isinstance(entry["values"], dict) or not set(entry["values"]) <= set(
            TEMPLATE_FIELDS
        ):
            raise DeclarationError("unknown template override field")
        entries[identifier] = entry
    resolved = {}
    chain_lengths = {}

    def resolve(identifier, ancestors=()):
        if identifier in ancestors:
            raise DeclarationError("template inheritance cycle")
        if len(ancestors) >= MAX_COMPONENT_CHAIN:
            raise DeclarationError("template inheritance limit exceeded")
        if identifier not in entries:
            raise DeclarationError("unknown template reference")
        if identifier in resolved:
            if len(ancestors) + chain_lengths[identifier] > MAX_COMPONENT_CHAIN:
                raise DeclarationError("template inheritance limit exceeded")
            return resolved[identifier]
        entry = entries[identifier]
        value = {}
        length = 1
        if entry["base"] is not None:
            value.update(resolve(entry["base"], (*ancestors, identifier)))
            length += chain_lengths[entry["base"]]
        value.update(entry["values"])
        validate_template_values(value)
        resolved[identifier] = value
        chain_lengths[identifier] = length
        return value

    for identifier in sorted(entries):
        resolve(identifier)
    return {identifier: resolved[identifier] for identifier in sorted(entries)}


def validate_template_bindings(profiles, templates):
    for profile in profiles:
        for identifier in profile["templates"].values():
            if identifier not in templates:
                raise DeclarationError(f"unknown template binding: {identifier}")


def rust_field(entry):
    variant = entry["variant"]
    if not FIELD_KEYS[variant]:
        return f"Field::{variant}"
    fields = []
    for name in FIELD_KEYS[variant]:
        value = entry[name]
        if name == "required":
            expression = str(value).lower()
        elif name == "attempt":
            expression = f"crate::ProxyAuthorizationAttempt::{value}"
        elif name in ("trustworthy", "untrustworthy", "unforwarded", "forwarded"):
            expression = rust_option(value, rust_string)
        else:
            expression = rust_string(value)
        fields.append(f"{name}: {expression}")
    return f"Field::{variant} {{ " + ", ".join(fields) + " }"


def generate_templates(templates):
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/request-templates.json.",
        "use super::request_template_values::{RequestFieldDefinition as Field, RequestTemplateDefinition};",
        "",
    ]
    for identifier, value in templates.items():
        lines += [
            "#[rustfmt::skip]",
            f"pub(super) static {identifier.upper()}: RequestTemplateDefinition = RequestTemplateDefinition {{",
        ]
        for name in TEMPLATE_FIELDS[:3]:
            fields = value[name]
            expression = (
                "None"
                if fields is None
                else "&[" + ", ".join(rust_field(entry) for entry in fields) + "]"
            )
            if name == "http3_fields" and fields is not None:
                expression = f"Some({expression})"
            lines.append(f"    {name}: {expression},")
        priority = value["http2_priority"]
        expression = "None"
        if priority is not None:
            expression = (
                "Some(crate::Http2Priority { "
                + ", ".join(
                    f"{name}: {str(priority[name]).lower()}"
                    for name in ("dependency_stream_id", "weight", "exclusive")
                )
                + " })"
            )
        lines.append(f"    http2_priority: {expression},")
        lines += [
            f"    {name}: {str(value[name]).lower()}," for name in TEMPLATE_FIELDS[-2:]
        ]
        lines += ["};", ""]
    return "\n".join(lines)
