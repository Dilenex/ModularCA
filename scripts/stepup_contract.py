#!/usr/bin/env python3
"""
Step-up contract auditor.

Finds admin UI calls that mutate a `[RequireStepUp]` endpoint using an api helper that never
attaches the `X-MFA-Token` header and never retries through the step-up modal. The result is a
403 the user cannot satisfy: the toast says "MFA re-verification required" and no prompt appears.

Role creation hit this in a live session. It is not a one-off — the same shape exists wherever a
page was written against `apiPost`/`apiPut`/`apiDelete` instead of the `*WithMfa` variants, and
nothing in the type system distinguishes them.

Also reports the inverse: a `requireStepUp` operation string the client sends that the server's
StepUpOps allow-list does not contain, which MfaStepUpController rejects up front with
`400 invalid_step_up_operation` — so the modal appears, the user completes MFA, and the request
still fails.

Usage:  python scripts/stepup_contract.py
Exit 1 if any mismatch is found.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROLLERS = ROOT / "ModularCA.API" / "Controllers"
ADMIN_UI = ROOT / "modularca.adminui" / "src"
STEPUP_OPS = ROOT / "ModularCA.Shared" / "Enums" / "StepUpOps.cs"

SKIP_PARTS = {"obj", "bin", "node_modules", "dist"}

ROUTE_RE = re.compile(r'\[Route\("([^"]+)"\)\]')
HTTP_RE = re.compile(r'\[Http(Get|Post|Put|Delete|Patch)(?:\("([^"]*)"\))?\]')
STEPUP_ATTR_RE = re.compile(r'\[RequireStepUp\(\s*StepUpOps\.(\w+)')
OPS_CONST_RE = re.compile(r'public const string (\w+)\s*=\s*"([^"]+)"')


def normalize(path: str) -> str:
    """Collapse route params so `{id:guid}` and `${id}` compare equal."""
    path = path.strip("/")
    path = re.sub(r"\{[^}]*\}", "{}", path)          # C#  {id:guid}
    path = re.sub(r"\$\{[^}]*\}", "{}", path)        # TS  ${id}
    return path.lower()


def server_stepup_routes() -> dict[str, tuple[str, str]]:
    """Maps normalized 'METHOD path' -> (op constant, source location)."""
    routes: dict[str, tuple[str, str]] = {}
    for cs in CONTROLLERS.rglob("*.cs"):
        if SKIP_PARTS & set(cs.parts):
            continue
        text = cs.read_text(encoding="utf-8", errors="replace")
        base_match = ROUTE_RE.search(text)
        if not base_match:
            continue
        base = base_match.group(1).replace("[controller]", "")

        lines = text.splitlines()
        for i, line in enumerate(lines):
            http = HTTP_RE.search(line)
            if not http:
                continue
            verb, sub = http.group(1).upper(), http.group(2) or ""

            # RequireStepUp sits within a couple of lines of the Http attribute.
            window = "\n".join(lines[max(0, i - 3): i + 4])
            op = STEPUP_ATTR_RE.search(window)
            if not op:
                continue

            full = normalize(f"{base}/{sub}" if sub else base)
            routes[f"{verb} {full}"] = (
                op.group(1),
                f"{cs.relative_to(ROOT).as_posix()}:{i + 1}",
            )
    return routes


def allowed_op_values() -> set[str]:
    """The literal strings StepUpOps.All accepts."""
    text = STEPUP_OPS.read_text(encoding="utf-8", errors="replace")
    consts = dict(OPS_CONST_RE.findall(text))
    all_block = re.search(r"All\s*=\s*(?:new\[\]\s*)?\{(.*?)\}", text, re.S)
    if not all_block:
        return set(consts.values())
    named = re.findall(r"\b(\w+)\b", all_block.group(1))
    return {consts[n] for n in named if n in consts}


UI_CALL_RE = re.compile(
    r"api(Post|Put|Delete)(WithMfa)?\(\s*[`'\"]([^`'\"]+)[`'\"]"
)
UI_OP_RE = re.compile(r"requireStepUp\s*,\s*'([^']+)'")


def main() -> int:
    stepup_routes = server_stepup_routes()
    allowed = allowed_op_values()

    unguarded: list[str] = []
    bad_ops: list[str] = []

    for f in ADMIN_UI.rglob("*.tsx"):
        if SKIP_PARTS & set(f.parts):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        rel = f.relative_to(ROOT).as_posix()

        for m in UI_CALL_RE.finditer(text):
            verb, with_mfa, path = m.group(1).upper(), m.group(2), m.group(3)
            if not path.startswith("/api/"):
                continue
            key = f"{verb} {normalize(path)}"
            if key in stepup_routes and not with_mfa:
                op, where = stepup_routes[key]
                line = text.count("\n", 0, m.start()) + 1
                unguarded.append(
                    f"  {rel}:{line}\n"
                    f"      {verb} {path}\n"
                    f"      requires StepUpOps.{op}  ({where})"
                )

        for m in UI_OP_RE.finditer(text):
            if m.group(1) not in allowed:
                line = text.count("\n", 0, m.start()) + 1
                bad_ops.append(f"  {rel}:{line}  '{m.group(1)}' is not in StepUpOps.All")

    print(f"step-up endpoints  : {len(stepup_routes)}")
    print(f"allowed operations : {len(allowed)}")
    print()

    if unguarded:
        print(f"{len(unguarded)} mutating call(s) on a step-up endpoint using a NON-MFA helper:")
        print("  (these 403 with 'MFA re-verification required' and no modal)\n")
        print("\n\n".join(unguarded))
        print()

    if bad_ops:
        print(f"{len(bad_ops)} step-up operation string(s) the server will reject:")
        print("  (MfaStepUpController answers 400 invalid_step_up_operation)\n")
        print("\n".join(bad_ops))
        print()

    if not unguarded and not bad_ops:
        print("No step-up contract mismatches found.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
