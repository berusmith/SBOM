"""Imports mako runtime helpers but never instantiates a Template — no
compilation path, so CVE-2022-40023 is not reachable here."""
from mako.runtime import Context
from io import StringIO


def make_context(initial: dict) -> Context:
    # Context wraps an output buffer; it does not parse template source.
    buf = StringIO()
    return Context(buf, **initial)
