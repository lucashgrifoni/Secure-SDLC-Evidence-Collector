"""RFC 3986 absolute-URI check, used before a locator becomes an OSCAL rlink.

The regular expression is the ``absolute-URI`` rule of RFC 3986 section 4.3
(``scheme ":" hier-part [ "?" query ]``) extended with the optional
``"#" fragment`` of the ``URI`` rule in section 3, built from the ABNF in
appendix A:

* ``authority = [ userinfo "@" ] host [ ":" port ]``;
* ``host = IP-literal / IPv4address / reg-name``, where ``IP-literal`` is an
  ``IPv6address`` or ``IPvFuture`` in brackets;
* ``hier-part`` is ``"//" authority path-abempty``, ``path-absolute``,
  ``path-rootless`` or ``path-empty``;
* ``pchar``, ``query`` and ``fragment`` allow unreserved characters,
  sub-delims, ``:``, ``@`` (and ``/``, ``?`` in query and fragment), and a
  ``%`` only as the start of a two-digit hex escape.

Anything else (a second ``#``, a space, ``[`` outside an IP literal, raw
non-ASCII text) is not a URI. RFC 3986 allows any number of port digits; a
port above 65535 is refused as well, because no transport can use it and
the previous ``urlsplit``-based check refused it too.
"""

from __future__ import annotations

import re

_PCT = r"%[0-9A-Fa-f]{2}"
_UNRESERVED = r"A-Za-z0-9\-._~"
_SUB_DELIMS = r"!$&'()*+,;="
_PCHAR = rf"(?:[{_UNRESERVED}{_SUB_DELIMS}:@]|{_PCT})"

_SCHEME = r"[A-Za-z][A-Za-z0-9+\-.]*"
_USERINFO = rf"(?:[{_UNRESERVED}{_SUB_DELIMS}:]|{_PCT})*"

_DEC_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4 = rf"{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}\.{_DEC_OCTET}"
_H16 = r"[0-9A-Fa-f]{1,4}"
_LS32 = rf"(?:{_H16}:{_H16}|{_IPV4})"
_IPV6 = "|".join(
    (
        rf"(?:{_H16}:){{6}}{_LS32}",
        rf"::(?:{_H16}:){{5}}{_LS32}",
        rf"(?:{_H16})?::(?:{_H16}:){{4}}{_LS32}",
        rf"(?:(?:{_H16}:){{0,1}}{_H16})?::(?:{_H16}:){{3}}{_LS32}",
        rf"(?:(?:{_H16}:){{0,2}}{_H16})?::(?:{_H16}:){{2}}{_LS32}",
        rf"(?:(?:{_H16}:){{0,3}}{_H16})?::{_H16}:{_LS32}",
        rf"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
        rf"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
        rf"(?:(?:{_H16}:){{0,6}}{_H16})?::",
    )
)
_IPVFUTURE = rf"[vV][0-9A-Fa-f]+\.[{_UNRESERVED}{_SUB_DELIMS}:]+"
_IP_LITERAL = rf"\[(?:{_IPV6}|{_IPVFUTURE})\]"
_REG_NAME = rf"(?:[{_UNRESERVED}{_SUB_DELIMS}]|{_PCT})*"
_HOST = rf"(?:{_IP_LITERAL}|{_IPV4}|{_REG_NAME})"
_AUTHORITY = rf"(?:{_USERINFO}@)?{_HOST}(?::(?P<port>[0-9]*))?"

_SEGMENT = rf"{_PCHAR}*"
_SEGMENT_NZ = rf"{_PCHAR}+"
_PATH_ABEMPTY = rf"(?:/{_SEGMENT})*"
_PATH_ABSOLUTE = rf"/(?:{_SEGMENT_NZ}(?:/{_SEGMENT})*)?"
_PATH_ROOTLESS = rf"{_SEGMENT_NZ}(?:/{_SEGMENT})*"
_HIER_PART = rf"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_ROOTLESS}|)"
_QUERY_OR_FRAGMENT = rf"(?:{_PCHAR}|[/?])*"

_ABSOLUTE_URI = re.compile(
    rf"{_SCHEME}:{_HIER_PART}(?:\?{_QUERY_OR_FRAGMENT})?(?:#{_QUERY_OR_FRAGMENT})?",
    re.ASCII,
)

_MAX_PORT = 65535


def is_absolute_uri(value: str) -> bool:
    """Whether ``value`` is an RFC 3986 URI with a scheme (fragment allowed)."""
    match = _ABSOLUTE_URI.fullmatch(value)
    if match is None:
        return False
    # Leading zeros are allowed; strip them before converting so a run of
    # thousands of digits is refused by length, not by int()'s digit limit.
    port = (match.group("port") or "").lstrip("0")
    return len(port) <= len(str(_MAX_PORT)) and (not port or int(port) <= _MAX_PORT)
