"""Covert-channel / protocol-metadata analysis.

Information can hide in *how* protocols speak, not just what they say:
which of two HTTP versions a request uses, the parity of IP IDs, the
choice among a handful of TTLs. This package finds fields whose values
vary systematically across otherwise-similar messages, maps the value
sequences to symbols, and tests whether the resulting bitstreams decode
to something structured — reporting every step as evidence, never as a
verdict.
"""

from netsleuth.covert.engine import analyze_capture   # noqa: F401
