"""Automatic Cookie field placement in compiled declarations."""

from .declarations import string_list
from .rust_literals import rust_string


def validate_cookie_values(values):
    string_list(values["before"], "Cookie placement names")


def rust_cookie_values(values):
    names = ", ".join(rust_string(name) for name in values["before"])
    return f"crate::CookiePlacement::before_fields::<_, &str>([{names}])"
