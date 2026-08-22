#!/usr/bin/env python3
"""
Wire-contract auditor.

Finds the bug class that shipped repeatedly in this codebase: the frontend reads a
JSON property under a spelling the backend never emits, gets `undefined`, masks it with
a `?? default`, and the next save writes that default over real data. Because API
responses are typed `any`, none of it is a compile error.

The check is a diff of two key sets:

  backend  - every JSON property name the API can emit, with System.Text.Json's
             camelCase policy applied exactly as the runtime applies it
  frontend - every property name the SPAs actually read

A frontend key is reported when it matches a backend key case-INSENSITIVELY but not
exactly. That pairing is the signature of the bug (`allowedEkus` vs `allowedEKUs`) and
is inherently low-noise: an unrelated DOM or library property will not collide with a
backend key while differing only in case.

Backend response shapes are read from SYNTAX, not reflection. 142 of this API's ~153
responses are anonymous objects built inline in the controller; reflection and
Swashbuckle both see those as opaque, so a DTO-driven generator would cover ~7% of the
surface. The member names are plainly visible in the source, and names are the whole
bug class.

Usage:  python scripts/wire_contract.py [--json] [--list-keys]
Exit 1 if any mismatch is found, so this can gate CI.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONTROLLER_ROOTS = [ROOT / "ModularCA.API" / "Controllers"]
MODEL_ROOTS = [
    ROOT / "ModularCA.Shared" / "Models",
    ROOT / "ModularCA.Shared" / "Entities",
    # EffectiveCertProfile and friends live here and ARE serialized to the admin UI,
    # so omitting this root silently blinds the audit to the profile surface.
    ROOT / "ModularCA.Core" / "Models",
    ROOT / "ModularCA.API" / "Models",
    ROOT / "ModularCA.Auth" / "Models",
    ROOT / "ModularCA.Bootstrap" / "Models",
]

# A frontend key shorter than this is almost always local UI state rather than an API
# field: the subject-DN form uses C, ST, L, O, OU as its own control names.
MIN_KEY_LEN = 3
SPA_DIRS = sorted(p for p in ROOT.glob("modularca.*") if (p / "src").is_dir())

SKIP_DIR_PARTS = {"obj", "bin", "node_modules", "dist", ".git"}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


# --------------------------------------------------------------------------- #
# System.Text.Json naming policy
# --------------------------------------------------------------------------- #
def camel_case(name: str) -> str:
    """
    Port of System.Text.Json's JsonNamingPolicy.CamelCase.

    It lowercases only the LEADING RUN of capitals, and stops early so the last capital
    of a run stays uppercase when a lowercase letter follows. This is why the wire name
    is `allowedEKUs` and not `allowedEkus`, and why `publishCRL` keeps its tail.
    """
    if not name or not name[0].isupper():
        return name
    chars = list(name)
    for i, c in enumerate(chars):
        if not c.isupper():
            break
        # Stop before the final capital of a run that is followed by lowercase.
        if i > 0 and i + 1 < len(chars) and not chars[i + 1].isupper():
            break
        chars[i] = c.lower()
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Minimal C# scrubber: blanks comments and string bodies so brace matching is safe
# --------------------------------------------------------------------------- #
def scrub_csharp(src: str) -> str:
    """
    Replace comment and string-literal CONTENT with spaces, preserving length and
    newlines so offsets and line numbers stay valid.

    Necessary because interpolated strings in this codebase contain braces
    (a logging message with an embedded expression), which would otherwise
    desynchronise brace depth.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        # block comment
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
            continue
        # verbatim string, doubled quote is an escape
        if c == "@" and i + 1 < n and src[i + 1] == '"':
            out[i] = " "
            i += 2
            while i < n:
                if src[i] == '"':
                    if i + 1 < n and src[i + 1] == '"':
                        out[i] = out[i + 1] = " "
                        i += 2
                        continue
                    break
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
            continue
        # regular or interpolated string
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    out[i] = " "
                    i += 1
                    if i < n:
                        out[i] = " "
                        i += 1
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
            continue
        # char literal
        if c == "'":
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\":
                    out[i] = " "
                    i += 1
                if i < n:
                    out[i] = " "
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


def match_brace(src: str, open_idx: int) -> int:
    """Index of the closing brace matching the one at open_idx, or -1. Input scrubbed."""
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top_level(body: str) -> list[str]:
    """Split an initializer body on commas that are not nested in brackets."""
    parts, depth, cur = [], 0, []
    for c in body:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def member_name(part: str) -> str | None:
    """
    Derive the emitted property name from one anonymous-object initializer element.

      Name = expr   -> Name          (explicit)
      finding.Id    -> Id            (member-access shorthand)
      revoked       -> revoked       (identifier shorthand)
    """
    part = part.strip()
    if not part:
        return None
    # explicit assignment, excluding ==, =>, <=, >=, !=
    m = re.match(r"^(" + IDENT + r")\s*=(?![=>])", part)
    if m:
        return m.group(1)
    # shorthand: bare identifier or trailing member access
    m = re.match(r"^(?:" + IDENT + r"\s*\.\s*)*(" + IDENT + r")$", part)
    if m:
        return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def iter_cs(roots) -> list[Path]:
    files = []
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*.cs"):
            if SKIP_DIR_PARTS & set(p.parts):
                continue
            files.append(p)
    return files


def extract_anonymous(files) -> dict[str, list[str]]:
    """Wire keys from anonymous objects built inline in controllers."""
    keys = defaultdict(list)
    pat = re.compile(r"\bnew\s*\{")
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="replace")
        src = scrub_csharp(raw)
        rel = path.relative_to(ROOT).as_posix()
        for m in pat.finditer(src):
            open_idx = src.index("{", m.start())
            close_idx = match_brace(src, open_idx)
            if close_idx < 0:
                continue
            body = src[open_idx + 1 : close_idx]
            line = raw.count("\n", 0, open_idx) + 1
            for part in split_top_level(body):
                name = member_name(part)
                if name:
                    keys[camel_case(name)].append(f"{rel}:{line}")
    return keys


PROP_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*"            # attributes
    r"public\s+"
    r"(?:static\s+|virtual\s+|override\s+|required\s+|readonly\s+|new\s+)*"
    r"[\w<>\[\],\.\?\s]+?\s+"            # type
    r"(" + IDENT + r")\s*"               # name
    r"(?:\{\s*get|=>)",                  # get accessor or expression-bodied
    re.MULTILINE,
)

JSON_NAME_RE = re.compile(r'JsonPropertyName\s*\(\s*"([^"]+)"\s*\)')


def extract_models(files) -> dict[str, list[str]]:
    """Wire keys from public properties of DTOs and entities."""
    keys = defaultdict(list)
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="replace")
        src = scrub_csharp(raw)
        rel = path.relative_to(ROOT).as_posix()
        # An explicit attribute wins over the naming policy.
        for m in JSON_NAME_RE.finditer(raw):
            line = raw.count("\n", 0, m.start()) + 1
            keys[m.group(1)].append(f"{rel}:{line}")
        for m in PROP_RE.finditer(src):
            line = raw.count("\n", 0, m.start()) + 1
            keys[camel_case(m.group(1))].append(f"{rel}:{line}")
    return keys


TS_SKIP_DIRS = {"node_modules", "dist", "build", ".vite"}

# No whitespace is allowed between the dot and the name. JSX renders prose as bare text
# that the scrubber cannot blank, and allowing a space matches the start of every
# sentence ("...the parent value. A CA can require fewer approvals").
TS_PROP_RE = re.compile(r"\.(" + IDENT + r")\b")
TS_INDEX_RE = re.compile(r"\[\s*['\"](" + IDENT + r")['\"]\s*\]")

# Reads chained off one of these are dictionary lookups, not property reads.
DICT_CHAIN_RE = None  # built at runtime from the C# model scan


def scrub_ts(src: str) -> str:
    """Blank comments and string bodies in TS/TSX so prose is not read as code."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
            continue
        if c in "\"'`":
            quote = c
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\":
                    out[i] = " "
                    i += 1
                if i < n and src[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


DICT_PROP_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*public\s+"
    r"(?:static\s+|virtual\s+|override\s+|required\s+|readonly\s+|new\s+)*"
    r"(?:Concurrent|IReadOnly|I)?Dictionary<\s*string\s*,[^>]*>\??\s+"
    r"(" + IDENT + r")\s*\{\s*get",
    re.MULTILINE,
)


def extract_dictionary_props(files) -> set[str]:
    """
    Wire names of properties whose VALUE is a string-keyed dictionary.

    Dictionary keys are not touched by the naming policy — JsonSerializerOptions
    .DictionaryKeyPolicy is unset in this app, so keys serialize verbatim. FieldSources
    is filled with `nameof(...)`, so `profile.fieldSources.AllowedKeyAlgorithms` is a
    correct PascalCase lookup, not a casing bug. Reads chained off these must not be
    compared against property names.
    """
    names: set[str] = set()
    for path in files:
        src = scrub_csharp(path.read_text(encoding="utf-8", errors="replace"))
        for m in DICT_PROP_RE.finditer(src):
            names.add(camel_case(m.group(1)))
    return names


def receiver_is_type(src: str, dot_idx: int) -> bool:
    """
    True when the thing being read from is a TYPE or NAMESPACE rather than API data.

    Deserialized API data is held in camelCase variables by convention, so an
    uppercase receiver means a C# type named in documentation prose
    (`SecurityPolicy.LoginResponseDelayMs` inside a docs page's <code> tag), a React
    component, or a JS builtin such as Object/JSON/Math. None of those are wire reads.
    """
    i = dot_idx
    if i > 0 and src[i - 1] == "?":  # optional chaining
        i -= 1
    end = i
    while i > 0 and (src[i - 1].isalnum() or src[i - 1] in "_$"):
        i -= 1
    return i < end and src[i].isupper()


def extract_frontend(dict_props: set[str]):
    """Returns (reads by key, keys read per file). The per-file index powers the
    dual-read rule: `params.changeType || params.ChangeType` is a deliberate fallback
    for legacy rows, not a mistake, and must not be reported."""
    suppress = (
        re.compile(
            r"\b(?:" + "|".join(sorted(map(re.escape, dict_props))) + r")\s*\??\.\s*"
            r"(" + IDENT + r")"
        )
        if dict_props
        else None
    )

    reads = defaultdict(list)
    file_keys: dict[str, set[str]] = defaultdict(set)
    for spa in SPA_DIRS:
        for p in (spa / "src").rglob("*"):
            if p.suffix not in (".ts", ".tsx"):
                continue
            if TS_SKIP_DIRS & set(p.parts):
                continue
            raw = p.read_text(encoding="utf-8", errors="replace")
            src = scrub_ts(raw)
            rel = p.relative_to(ROOT).as_posix()

            # Spans of names that are dictionary lookups rather than property reads.
            skip = set()
            if suppress:
                for m in suppress.finditer(src):
                    skip.add(m.span(1))

            for rx in (TS_PROP_RE, TS_INDEX_RE):
                for m in rx.finditer(src):
                    if m.span(1) in skip:
                        continue
                    if len(m.group(1)) < MIN_KEY_LEN:
                        continue
                    if receiver_is_type(src, m.start()):
                        continue
                    line = src.count("\n", 0, m.start()) + 1
                    reads[m.group(1)].append(f"{rel}:{line}")
                    file_keys[rel].add(m.group(1))
    return reads, file_keys


# Golden pairs verified against JsonNamingPolicy.CamelCase.ConvertName on .NET 10.
# The full check ran over all 1223 property and anonymous-member names in this repo with
# zero mismatches; these are the cases that actually discriminate between the real
# algorithm and the "just lowercase the first letter" approximation.
POLICY_GOLDEN = [
    ("AllowedEKUs", "allowedEKUs"),
    ("PublishCRL", "publishCRL"),
    ("CRLDistributionPoints", "crlDistributionPoints"),
    ("ID", "id"),
    ("EKUs", "ekUs"),
    ("OAuth2ClientId", "oAuth2ClientId"),
    ("IPAddress", "ipAddress"),
    ("SANRules", "sanRules"),
    ("CTEnabled", "ctEnabled"),
    ("WebAuthnEnabled", "webAuthnEnabled"),
    ("Username", "username"),
    ("alreadyCamel", "alreadyCamel"),
    ("A", "a"),
    ("", ""),
]


def self_test() -> int:
    bad = [(n, camel_case(n), want) for n, want in POLICY_GOLDEN if camel_case(n) != want]
    for n, got, want in bad:
        print(f"FAIL {n!r}: got {got!r}, want {want!r}")
    print(f"camelCase policy: {len(POLICY_GOLDEN) - len(bad)}/{len(POLICY_GOLDEN)} passed")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--list-keys", action="store_true", help="dump both key sets")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="check the camelCase port against known-good values",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    controllers = iter_cs(CONTROLLER_ROOTS)
    models = iter_cs(MODEL_ROOTS)

    anon = extract_anonymous(controllers)
    dto = extract_models(models)

    backend: dict[str, list[str]] = defaultdict(list)
    for source in (anon, dto):
        for k, v in source.items():
            backend[k].extend(v)

    dict_props = extract_dictionary_props(models)
    frontend, file_keys = extract_frontend(dict_props)

    # Index backend keys by lowercase for the case-insensitive collision test.
    by_lower: dict[str, set[str]] = defaultdict(set)
    for k in backend:
        by_lower[k.lower()].add(k)

    findings = []
    for fkey, sites in sorted(frontend.items()):
        if fkey in backend:
            continue  # exact match, correct
        candidates = by_lower.get(fkey.lower())
        if not candidates:
            continue  # unrelated to the API surface

        # Dual-read rule: if the same file also reads a correct spelling of this key,
        # the odd-cased read is a deliberate fallback covering rows written before a
        # casing change. Only sites with no such fallback are real.
        bare = sorted(
            {
                s
                for s in set(sites)
                if not (candidates & file_keys[s.rsplit(":", 1)[0]])
            }
        )
        if not bare:
            continue

        findings.append(
            {
                "frontendKey": fkey,
                "backendKeys": sorted(candidates),
                "readSites": bare,
                "emitSites": sorted({s for c in candidates for s in backend[c]}),
            }
        )

    if args.list_keys:
        print(f"backend keys: {len(backend)}")
        for k in sorted(backend):
            print(f"  {k}")
        print(f"\nfrontend keys: {len(frontend)}")
        for k in sorted(frontend):
            print(f"  {k}")
        return 0

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
        return 1 if findings else 0

    print(f"controllers scanned : {len(controllers)}")
    print(f"model files scanned : {len(models)}")
    print(f"backend wire keys   : {len(backend)}")
    print(f"frontend read keys  : {len(frontend)}")
    print()

    if not findings:
        print("No casing mismatches found.")
        return 0

    print(f"{len(findings)} casing mismatch(es):\n")
    for f in findings:
        print(f"  {f['frontendKey']}  ->  backend emits {', '.join(f['backendKeys'])}")
        for s in f["readSites"][:6]:
            print(f"      read  {s}")
        if len(f["readSites"]) > 6:
            print(f"      ... and {len(f['readSites']) - 6} more read sites")
        for s in f["emitSites"][:3]:
            print(f"      emit  {s}")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
