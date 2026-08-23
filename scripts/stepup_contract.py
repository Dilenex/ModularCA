#!/usr/bin/env python3
"""
Step-up contract auditor.

Finds admin UI calls that mutate a `[RequireStepUp]` endpoint using an api helper that never
attaches the `X-MFA-Token` header and never retries through the step-up modal. The result is a
403 the user cannot satisfy: the toast says "MFA re-verification required" and no prompt appears.

Role creation hit this in a live session. It is not a one-off — the same shape exists wherever a
page was written against `apiPost`/`apiPut`/`apiDelete` instead of the `*WithMfa` variants, and
nothing in the type system distinguishes them.

Also reports the inverse: a `requireStepUp` operation the client sends that the server's
StepUpOps allow-list does not contain, which MfaStepUpController rejects up front with
`400 invalid_step_up_operation` — so the modal appears, the user completes MFA, and the request
still fails.

Since those operations became generated constants (`shared/common/src/generated/stepUpOps.ts`,
built from `StepUpOps.All`), naming an unregistered one no longer compiles. Two checks remain
worth running: a constant the generated file no longer defines means the checked-in output is
stale, and a bare string literal means a call site escaped the migration and is back to failing
at runtime instead of at build time. Both are reported.

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


def allowed_ops() -> dict[str, str]:
    """Constant name -> wire value, for every member of StepUpOps.All."""
    text = STEPUP_OPS.read_text(encoding="utf-8", errors="replace")
    consts = dict(OPS_CONST_RE.findall(text))
    all_block = re.search(r"All\s*=\s*(?:new\[\]\s*)?\{(.*?)\}", text, re.S)
    if not all_block:
        return consts
    named = re.findall(r"\b(\w+)\b", all_block.group(1))
    return {n: consts[n] for n in named if n in consts}


UI_CALL_RE = re.compile(
    r"api(Post|Put|Delete)(WithMfa)?(?:<[^()]*?>)?\(\s*[`'\"]([^`'\"]+)[`'\"]"
)

# Operations are now passed as generated constants (StepUpOps.RevokeCert), not literals. The
# constant form cannot name an operation the server rejects — shared/common/src/generated is
# built from StepUpOps.All, so an unregistered name does not exist to import. Both forms are
# still matched: the constant so a stale generated file is caught, the literal so a hand-written
# string that slipped back in is reported rather than silently trusted.
UI_OP_CONST_RE = re.compile(r"requireStepUp\s*,\s*StepUpOps\.(\w+)")
UI_OP_LITERAL_RE = re.compile(r"requireStepUp\s*,\s*'([^']+)'")


def main() -> int:
    stepup_routes = server_stepup_routes()
    allowed = allowed_ops()

    unguarded: list[str] = []
    bad_ops: list[str] = []
    literals: list[str] = []
    checked_ops = 0

    # .ts as well as .tsx: src/api/scheduler.ts holds ten step-up call sites and was invisible to
    # this auditor while it only globbed components.
    sources = sorted(set(ADMIN_UI.rglob("*.tsx")) | set(ADMIN_UI.rglob("*.ts")))
    for f in sources:
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

        for m in UI_OP_CONST_RE.finditer(text):
            checked_ops += 1
            if m.group(1) not in allowed:
                line = text.count("\n", 0, m.start()) + 1
                bad_ops.append(
                    f"  {rel}:{line}  StepUpOps.{m.group(1)} is not in the C# StepUpOps.All "
                    f"(regenerate: node scripts/generate-shared-types.mjs)"
                )

        for m in UI_OP_LITERAL_RE.finditer(text):
            checked_ops += 1
            line = text.count("\n", 0, m.start()) + 1
            if m.group(1) not in allowed.values():
                bad_ops.append(f"  {rel}:{line}  '{m.group(1)}' is not in StepUpOps.All")
            else:
                literals.append(
                    f"  {rel}:{line}  '{m.group(1)}' - use the generated StepUpOps constant"
                )

    print(f"step-up endpoints  : {len(stepup_routes)}")
    print(f"allowed operations : {len(allowed)}")
    print(f"client op usages   : {checked_ops}")
    print()

    # A zero here means the extraction stopped matching, not that the code is clean. The op
    # argument changed shape once already (literal -> StepUpOps constant) and silently emptied
    # this check; say so rather than printing a reassuring pass.
    if checked_ops == 0:
        print("No client step-up operations matched — the call shape has changed and this")
        print("auditor is no longer inspecting anything. Fix the extraction, not this message.")
        return 1

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

    if literals:
        print(f"{len(literals)} step-up operation(s) still passed as a bare string literal:")
        print("  (valid today, but a typo here is a runtime 400 instead of a build error)\n")
        print("\n".join(literals))
        print()

    if not unguarded and not bad_ops and not literals:
        print("No step-up contract mismatches found.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
