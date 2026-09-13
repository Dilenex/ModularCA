# Open core: where code lives, and why

ModularCA is AGPL-3.0. Some features are sold. This is the note that keeps those two facts from
quietly corrupting each other.

There are no private modules today — every line of the product is in this repository. This exists
so that stays deliberate rather than accidental, and so the first private module has somewhere to
attach without a refactor.

## The invariant

> **A private module may reference the open-source projects. The open-source projects may never
> reference a private module.**

The dependency arrow points one way. This repository has to build, test and ship standalone: no
submodule, no conditional compilation, no stub project, no `#if ENTERPRISE`, no hole where private
code would go.

The reason is not purity. A free edition with a gap in it is broken for everyone who clones it,
and they find out on their first build — which is the opposite of what an open core is for. The
free tier is the distribution channel; breaking it to protect revenue trades the thing that
generates demand for the thing that captures it.

Two properties of the project graph make this possible, and
`tests/ModularCA.Tests/Architecture/ModuleBoundaryTests.cs` asserts both:

- **`ModularCA.Shared` references nothing.** It holds the interfaces, error codes, entitlement
  contract and licence catalogue, so it is what a private module compiles against. Give it a
  project reference and every module inherits a transitive graph — eventually the database and the
  keystore — to get at a handful of types.
- **Nothing references `ModularCA.API`.** It is the composition root and a leaf. An enterprise
  build composes around it; a reference into it would put a cycle exactly where the extension point
  has to go.

The layer order is `Shared → Database → Keystore → Core → Auth → Bootstrap → API`, and a project
may only reference projects below it.

## Two ways a feature can be paid, and they are not interchangeable

**Licence-gated open code.** The implementation is here, under AGPL, readable and forkable. What is
sold is the right to use it past the free threshold, enforced with a clear refusal and an audit
record — `TenantCreationGate` is the worked example. Enforcement is honour-system; the protection
is the licence agreement and the audit trail, not the `if` statement.

**Private module.** Code that genuinely is not in this repository. The only mechanism that
withholds anything, and it can only ever apply to work not yet published.

That second clause is the whole game. **AGPL is a one-way door.** A feature released here is free
at that version forever. Publishing is irreversible in a way that no licence term can undo.

## Two rules that follow

**Decide a feature's home before writing it, not after.** This is the rule that actually slips,
because the decision feels postponable and never is. By the time the code works, the decision has
already been made by default.

**Never move published code private.** The CLA makes it legal. It does not make it safe. Taking
something the community has been using and closing it is the most reliable way to poison an
open-source project — and you would be doing it to the same people you are asking to advocate for
the product at work. AGPL mostly enforces this anyway: the old version stays free, so you would be
closing a door already off its hinges.

New code may start private. Existing code never becomes private.

## Gating a feature that lives here

Use `FeatureGate`. It exists so that adding a gate is a decision rather than a chore, and so every
licensing refusal reads the same way to the operator who hits it.

```csharp
var refusal = FeatureGate.Require(
    entitlements, FeatureKeys.BackupOrchestration,
    "Scheduling off-host backups",
    "Manual backup and restore are unaffected.");

if (refusal is not null)
{
    await _audit.LogAsync(/* ... */);   // audit BEFORE throwing — see below
    throw refusal;
}
```

Three things are load-bearing:

- **Audit before you throw.** A refused attempt to exceed a licence limit is the event a commercial
  dispute later turns on. `FeatureGate` returns rather than throws precisely so the correct ordering
  is expressible.
- **Say what still works.** An operator refused mid-task assumes the worst — that issuance has
  stopped, that something they built is now unusable. A feature where nothing can be said in that
  sentence is a feature that should not be gated this way.
- **Gate at one site if you can.** Multi-tenancy is gateable because there is exactly one runtime
  tenant-creation site, even though `TenantId` reaches 786 places. A feature with no such chokepoint
  is a poor candidate for licence-gating and probably wants to be a module instead.

## What is deliberately not built yet

**No plugin API, no DI extension hook, no module discovery.** Designing an extension point before
there is anything to extend produces an abstraction that fits nothing. When the first module is
written, extract the seam from working code.

The likely shape, for whenever that is: `ModularCA.API` composes services inline in
`StartModularCA.cs`, so an enterprise entry point currently has no way in. The minimal fix is an
optional `Action<IServiceCollection>` the enterprise `Program` passes its registrations through —
one parameter, no framework. .NET resolves the last registration for a given service type, so a
module registering after the built-ins overrides them without any `TryAdd` ceremony.

**No runtime assembly loading.** Tempting — one binary, drop modules in a directory. Do not, not in
a CA. It adds arbitrary assembly loading to a trust anchor, which is a supply-chain surface
invented for no reason, and it makes the entitlement check bypassable by not loading the checker.
Two build artifacts instead: this repository builds the community edition, the private repository
builds community-plus-modules.

## When the private repository does appear

- It consumes this one (pinned to a tag), never the reverse.
- The root `VERSION` file stays the single source of truth — both MSBuild and every
  `vite.config.ts` already read it. A release is tag-public, bump-pin, tag-private. Two
  repositories, one version number, one meaning.
- Public CI must stay fully self-contained. A public job that needs a private secret is a leak
  waiting for a misconfigured log.
- Anyone with private repository access needs IP assignment in writing **before their first
  commit** — contractors especially, where the default in many jurisdictions is that they own what
  they write. Without it their work cannot be relicensed commercially, and that is discovered at
  the worst possible moment.
