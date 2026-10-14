"""Closed ordered client hints and the existing Android model parameter."""

from .declarations import MAX_STRING, DeclarationError, choice, keys, text
from .rust_literals import rust_string

TOKEN_CHARACTERS = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")


def validate_hint_string(value, model=False):
    if (
        not isinstance(value, str)
        or len(value) > MAX_STRING
        or not all(" " <= char <= "~" or (not model and char == "\t") for char in value)
    ):
        raise DeclarationError("hint values must be bounded ASCII header strings")


def validate_client_hints_values(values):
    hints = values["hints"]
    if not isinstance(hints, list) or len(hints) > 64:
        raise DeclarationError("hints must be a list of at most 64 records")
    names = set()
    for hint in hints:
        keys(hint, ("name", "delivery", "value"), "client hint")
        name = text(hint["name"], "hint name")
        if not "a" <= name[0] <= "z" or not all(
            char in TOKEN_CHARACTERS for char in name
        ):
            raise DeclarationError(
                "hint names must be lowercase ASCII tokens starting a-z"
            )
        if name in names:
            raise DeclarationError("hint names must not repeat")
        names.add(name)
        delivery = choice(hint["delivery"], ("Default", "AcceptCh"), "hint delivery")
        value = hint["value"]
        if not isinstance(value, dict):
            raise DeclarationError("hint value must be a typed record")
        kind = choice(value.get("kind"), ("Literal", "Model"), "hint value kind")
        if kind == "Literal":
            keys(value, ("kind", "value"), "literal hint value")
            validate_hint_string(value["value"])
        else:
            keys(value, ("kind", "default"), "model hint value")
            if name != "sec-ch-ua-model" or delivery != "AcceptCh":
                raise DeclarationError(
                    "only the requested model hint has a model parameter"
                )
            validate_hint_string(value["default"], model=True)


def model_hint(values):
    return next(
        (hint for hint in values["hints"] if hint["value"]["kind"] == "Model"), None
    )


def validate_hint_function_names(components):
    names = {component["id"] for component in components}
    for component in components:
        if component["kind"] == "ClientHintSettings" and model_hint(
            component["values"]
        ):
            parameter_name = component["id"] + "_for_model"
            if parameter_name in names:
                raise DeclarationError(
                    "generated model function name conflicts with a component"
                )
            names.add(parameter_name)


def generate_client_hints_component(component):
    identifier = component["id"]
    model = model_hint(component["values"])
    lines = ["#[rustfmt::skip]"]
    if model:
        lines.extend(
            [
                f"pub(crate) fn {identifier}() -> crate::ClientHintSettings {{",
                f"    {identifier}_for_model({rust_string(model['value']['default'])})",
                "}",
                "",
                "#[rustfmt::skip]",
                f"pub(crate) fn {identifier}_for_model(model: &str) -> crate::ClientHintSettings {{",
            ]
        )
    else:
        lines.append(f"pub(crate) fn {identifier}() -> crate::ClientHintSettings {{")
    lines.append("    crate::ClientHintSettings::new(vec![")
    for hint in component["values"]["hints"]:
        value = hint["value"]
        expression = (
            "crate::browser::chrome::model_value(model)"
            if value["kind"] == "Model"
            else rust_string(value["value"])
        )
        lines.append(
            f"        crate::ClientHint::new({rust_string(hint['name'])}, {expression}, "
            f"crate::ClientHintDelivery::{hint['delivery']}),"
        )
    lines.extend(["    ])", "}", ""])
    return lines
