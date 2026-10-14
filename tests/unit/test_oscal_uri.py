"""RFC 3986 absolute-URI validation used before an OSCAL rlink is emitted."""

from __future__ import annotations

import pytest

from evidence_collector.exporters._uri import is_absolute_uri

# RFC 3986 section 1.1.2, verbatim.
RFC_3986_EXAMPLES = [
    "ftp://ftp.is.co.za/rfc/rfc1808.txt",
    "http://www.ietf.org/rfc/rfc2396.txt",
    "ldap://[2001:db8::7]/c=GB?objectClass?one",
    "mailto:John.Doe@example.com",
    "news:comp.infosystems.www.servers.unix",
    "tel:+1-816-555-1212",
    "telnet://192.0.2.16:80/",
    "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
]


@pytest.mark.parametrize("uri", RFC_3986_EXAMPLES)
def test_rfc_3986_examples_are_absolute_uris(uri: str) -> None:
    assert is_absolute_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "https://ci.example/run/7/trivy.sarif",
        "https://example.test/trivy%20report.sarif",
        "https://user:pa%20ss@example.test:8443/a/b;c?x=1&y=/?#frag/?:@",
        "http://example.test:/empty-port",
        "http://example.test:65535/",
        "http://example.test:00080/",
        "http://example.test:" + "0" * 5000 + "80/",
        "http://[::1]/",
        "http://[::]/",
        "http://[fe80::1:2:3:4]:8080/x",
        "http://[2001:db8:0:0:0:0:2:1]/",
        "http://[::ffff:192.0.2.128]/",
        "http://[1:2:3:4:5:6:7::]/",
        "http://[v7.fe80::abcd:x]/",
        "http://192.0.2.16/",
        "http://999.1.1.1/",
        "file:///C:/ci/trivy.sarif",
        "file://server/share/trivy.sarif",
        "file:///srv/ci/trivy%20report.sarif",
        "s3://bucket/key",
        "c:/foo",
        "x:",
        "a+b-c.d:rootless/path",
        "http://",
        "http://example.test?q",
        "http://example.test#f",
    ],
)
def test_other_well_formed_absolute_uris_are_accepted(uri: str) -> None:
    assert is_absolute_uri(uri)


@pytest.mark.parametrize(
    "uri",
    [
        "https://example.test/a#one#two",
        "https://ci.example/a b?x=1#frag",
        "https://example.test/%zz",
        "https://example.test/50%",
        "https://example.test/%4",
        "http://[",
        "http://[::1/",
        "http://[::g]/",
        "http://[1:2:3:4:5:6:7:8:9]/",
        "http://[1::2::3]/",
        "http://[fe80::1]x/",
        "http://[v.x]/",
        "https://example.test:abc/report.json",
        "https://example.test:99999/report.json",
        "http://example.test:65536/",
        "http://example.test:" + "9" * 5000 + "/",
        "http://user@host@example.test/",
        "http://exa[mple.test/",
        "https://example.test/a[1].json",
        "https://example.test/r.json?y=[1]",
        "https://example.test/r.json#[x]",
        "mailto:a[b]@example.test",
        ":no-scheme",
        "",
        "1http://example.test/",
        "+http://example.test/",
        "ht_tp://example.test/",
        "https://exämple.test/",
        "https://example.test/relatório",
        "https://example.test/a\nb",
        "https://example.test/a\\b",
        'https://example.test/"q"',
        "https://example.test/<x>",
        "https://example.test/{x}",
        "https://example.test/a|b",
        "https://example.test/a^b",
        "https://example.test/`b`",
        "relative/thing.json",
        "//example.test/network-path",
        "/absolute/path",
        "C:\\ci\\trivy.sarif",
    ],
)
def test_structurally_invalid_or_relative_references_are_rejected(uri: str) -> None:
    assert not is_absolute_uri(uri)


def test_a_long_uri_without_an_at_sign_is_checked_quickly() -> None:
    # The userinfo group backtracks when no "@" follows; it must stay linear.
    assert is_absolute_uri("https://" + "a" * 200_000 + "/x")
    assert not is_absolute_uri("https://" + "a" * 200_000 + " /x")
