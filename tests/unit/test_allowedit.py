"""`agentbox allow` text edit of [network] allow (comments kept, idempotent)."""

import tomllib

import pytest
from agentbox.allowedit import AllowEditError, add_allow
from agentbox.template import render_default_profile

TEMPLATE = render_default_profile("p", "/work/p")


def allow_of(text):
    return tomllib.loads(text)["network"]["allow"]


def test_template_empty_array():
    new, changed = add_allow(TEMPLATE, "Example.COM")
    assert changed and allow_of(new) == ["example.com"]
    # every other line kept byte for byte
    diff = [(a, b) for a, b in zip(TEMPLATE.splitlines(), new.splitlines(), strict=True) if a != b]
    assert diff == [("allow = []", 'allow = ["example.com"]')]
    assert "# CLAUDE_CODE_OAUTH_TOKEN is implicit" in new


def test_idempotent():
    once, _ = add_allow(TEMPLATE, "example.com")
    twice, changed = add_allow(once, "EXAMPLE.com")
    assert not changed and twice == once
    third, changed = add_allow(once, "b.org")
    assert allow_of(third) == ["example.com", "b.org"]


def test_multiline_with_comments():
    text = (
        '# top\n[network]\nmode = "strict"  # keep\nallow = [\n'
        '  "a.com",   # why a\n  # a comment line\n  "b.com"  # no comma\n]\n'
        'allow_http = false\n\n[models]\nollama = "local"\n'
    )
    new, changed = add_allow(text, "c.com")
    assert changed and allow_of(new) == ["a.com", "b.com", "c.com"]
    assert "# why a" in new and "# a comment line" in new and "# no comma" in new
    assert "# keep" in new and new.startswith("# top\n")
    assert tomllib.loads(new)["network"]["allow_http"] is False


def test_multiline_trailing_comma_and_bracket_on_item_line():
    t1 = '[network]\nallow = [\n  "a.com",\n]\n'
    assert allow_of(add_allow(t1, "x.org")[0]) == ["a.com", "x.org"]
    t2 = '[network]\nallow = [\n  "a.com"]\n'
    assert allow_of(add_allow(t2, "x.org")[0]) == ["a.com", "x.org"]


def test_single_line_variants():
    for t in ('[network]\nallow = ["a.com"]\n', '[network]\nallow = [ "a.com", ]  # c\n'):
        new, _ = add_allow(t, "x.org")
        assert allow_of(new) == ["a.com", "x.org"]
    assert "# c" in add_allow('[network]\nallow = [ "a.com", ]  # c\n', "x.org")[0]


def test_missing_key_or_section():
    t = '[network]\nmode = "open"\n# trailing comment\n\n[models]\nollama = "local"\n'
    new, _ = add_allow(t, "x.org")
    assert allow_of(new) == ["x.org"] and tomllib.loads(new)["network"]["mode"] == "open"
    t2 = '[[mount]]\nhost = "/w"\n'
    new2, _ = add_allow(t2, "x.org")
    assert allow_of(new2) == ["x.org"] and tomllib.loads(new2)["mount"] == [{"host": "/w"}]


def test_brackets_inside_strings_and_comments():
    t = '[network]\nallow = [\n  "a.com", # ] tricky\n]\n[box]\nagents = ["claude"]\n'
    new, _ = add_allow(t, "x.org")
    assert allow_of(new) == ["a.com", "x.org"]
    assert tomllib.loads(new)["box"]["agents"] == ["claude"]


@pytest.mark.parametrize(
    "bad",
    ["1.2.3.4", "http://a.com", "a.com:443", "*.a.com", "localhost", "x.internal", "single",
     "mcp-proxy.anthropic.com", ".anthropic.com", ""],
)  # fmt: skip
def test_invalid_rejected(bad):
    with pytest.raises(AllowEditError):
        add_allow(TEMPLATE, bad)


def test_non_plain_forms_refused():
    with pytest.raises(AllowEditError, match="not a plain table"):
        add_allow('network = { mode = "strict" }\n', "x.org")
    with pytest.raises(AllowEditError, match="not valid TOML"):
        add_allow("[network\n", "x.org")


def test_crlf_preserved():
    crlf = TEMPLATE.replace("\n", "\r\n")
    new, changed = add_allow(crlf, "example.com")
    assert changed and "\n" not in new.replace("\r\n", "")
    assert new.replace("\r\n", "\n") == add_allow(TEMPLATE, "example.com")[0]
    assert add_allow(new, "example.com") == (new, False)
    with pytest.raises(AllowEditError, match="mixed"):
        add_allow("[network]\r\nallow = []\n", "x.org")
