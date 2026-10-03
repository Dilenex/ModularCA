# The instance is the tenant

Status: accepted 2026-09-26; the work is release 0.4.0. No deployment runs more than one non-system tenant, so nothing
has to be migrated before the change starts.

## Why

Tenancy today is a row property. 19 of 74 entities carry a `TenantId`, four global query
filters enforce it, and anonymous protocol traffic runs outside those filters. Isolation holds
only as long as every query remembers the tenant, and the full review of 2026-09-26 found many
places where one did not:

- CA labels resolved across tenants.
- OCSP and CRL matched a CA by subject name.
- ACME EAB keys had no tenant at all.
- Enrollment tokens were redeemable at any CA.
- Protocol audit was scoped by label.
- Request bodies could retarget a profile at another tenant's CA.

The three-level rank model (system, tenant, CA) that the controlled-user ceremony has to
reason about exists because of the same design.

Each fix closes one query, and the next feature opens another. The boundary is in the wrong
place.

## Decision

The isolation boundary is the instance: one process group, one database, one keystore, one
signer, one audit chain. A customer is an instance. Inside an instance there is one
organisation. What tenants are used for today — grouping CAs and delegating their
administration — becomes a **space**, which is a scope for access control and not a partition
of data.

A separate, paid **visor** manages a fleet of instances through their APIs. It does not share
a database with them.

```
Visor                   fleet registry · backups · upgrades · central view
  │  API, scoped and pinned identity, either dial direction
  ├── Instance: Client A     own DB, keystore, signer, audit chain
  │     ├── Space: Corp IT   delegation only
  │     │     └── CAs → profiles → enrollment endpoints
  │     └── Space: Plant
  ├── Instance: Client B
  └── Instance: MSP          may hold a root that signs client intermediates
```

### Inside an instance

- **Instance-wide settings belong to the instance.** The system tenant is retired.
- **Ranks are instance admin, space admin, CA admin and operator.** The controlled-user
  ceremony keeps its rules — quorum, the initiator never counts, the approver must dominate —
  over this smaller set.
- **An instance serves its own hostnames.** Tenant hostnames, SNI routing by tenant and the
  tenant ingress routes leave the product. Routing to instances is the job of whatever stands
  in front of them, which can be the visor.
- **Labels, subject names and serials need only be unique within the instance**, which is
  the only scope that exists.

### Across instances

- **Trust between instances is an explicit ceremony, never a shared key.** An MSP that wants
  one root over many clients keeps it in its own instance. A client instance produces an
  intermediate CSR, the visor carries it, the MSP instance signs it under a ceremony, and the
  certificate goes back the same way. Name constraints on that intermediate are the contract
  shown to the client.
- **Anything fleet-wide is aggregated by the visor from instance APIs.** That covers search,
  reporting and expiry dashboards.

### The visor's authority

The visor is the most powerful thing in the fleet, so its power is bounded at every instance
it manages:

- **It authenticates with a pinned identity bound to a scoped role on each instance.** It can
  read inventory, trigger backups and stage upgrades. It cannot export a private key, and it
  cannot satisfy a ceremony on its own: quorum stays local to the instance.
- **Backups leave the instance already encrypted.** The visor stores ciphertext and never
  holds the key that opens it.
- **Every visor action is recorded in the instance's own audit chain**, attributed to the
  visor identity.

## Connectivity

Either side may open the connection. Which one did is recorded on both sides — in the
instance's configuration and audit, and in the visor's registry — and shown to the operator
with the caveats below when the instance is enrolled and in the visor afterwards.

**The visor dials the instance.**

- The instance exposes its management API inbound. At a client site that means a firewall
  rule or port forward, and an admin surface reachable from outside the site.
- The instance must accept only the pinned visor identity on that listener. The listener is
  separate from the one that serves enrollment protocols, so it can be firewalled on its own.
- The visor sees the instance whenever the network allows, and needs no agent state.

**The instance dials the visor.**

- No inbound opening is needed, and it works behind NAT. This is the usual choice for
  client-site instances.
- The instance holds a persistent outbound channel, and visor requests arrive over it. The
  instance still authenticates the visor on that channel by its pinned identity. That the
  instance opened the connection proves nothing about who answered.
- Egress filtering or an intercepting proxy at the site can break the channel. While it is
  down, the visor loses visibility and its requests queue. The instance keeps issuing and
  revoking regardless, because nothing the instance does depends on the visor being reachable.

**In both directions:**

- A compromised visor reaches every instance it manages. The scoped role, local quorum and
  ciphertext-only backups are what limit that, not the dial direction.

## Order of work

1. **Single-organisation mode.** Refuse to create a second non-system tenant unless an
   explicit flag is set. No deployment has one, so this is a default change, not a migration.
2. **Close what matters within one organisation.** From the review, these stay regardless of
   tenancy:
   - enrollment tokens bound to their CA;
   - ACME accounts bound to their CA;
   - revoked or disabled CAs refused at issuance;
   - OCSP and CRL resolved by CA key or id rather than subject name;
   - request bodies authorised against the target they name.

   The purely cross-tenant fixes reduce to step 1.
3. **Tenant becomes space.** The foreign keys mostly survive under a new meaning. Remove
   query filters and routing that exist only for isolation, and scope delegation through the
   space.
4. **Fold the system tenant into the instance.** Retire tenant hostnames and tenant ingress
   routes.
5. **The visor**, starting with enrolment of an instance and its recorded dial direction, then
   inventory, ciphertext backup and restore, then staged upgrades. A tool to split a
   multi-tenant instance into instances is only needed if a deployment ever has one.

## Decisions for 0.4.0 (2026-09-26)

- **Schema changes arrive as EF migrations.** Production and staging have run
  `20260919181506_InitialCreate` (and the audit context's `InitialAuditSchema`) since
  2026-09-19. Regenerating a baseline that a live database has applied leaves that database on
  the old schema, whichever id the new baseline takes. Both baselines are therefore frozen.
  Every schema change from 0.4.0 on is a migration, with any data transformation written into
  it. Each migration checks its preconditions first and raises, rolling back, when one fails.
  The control role stops if a migration fails, instead of starting on a stale schema.
- **The delegation scope is a space, and an instance may have several.** A space is an access
  scope. It is not a partition of data.
- **`/admin/tenants` is replaced by `/admin/spaces` with no alias.** The console ships with the
  server and is the only known consumer.
- **Tenant hostnames are removed without a cutover.** Neither live deployment serves one.
- **Defaults, unless revisited:**
  - Where the system and organisation tenants disagree on a setting, the stricter value wins.
    **Replaced for S3 (owner decision):** policy scopes are independent, not a floor. The
    instance's policy governs instance CAs only and a space's governs its own CAs only; nothing
    merges, and the fold copies the system tenant's values to the instance as they are.
  - Super remains as the break-glass rank, and a space-wide operator rank is kept.
  - Tenant quotas are removed; group quotas stay.
  - The multi-tenancy licence flag moves to the visor.
  - Per-tenant audit chains stay as recorded, because `TenantId` is inside every hash. They
    verify as earlier epochs, and new records go to one instance chain.

## Stages of 0.4.0

Each stage builds, passes the tests and leaves the product working. The rename comes last, so
that nothing is renamed only to be deleted.

- **S0.** Freeze the baselines. Make a failed migration stop the control role. Add an opt-in
  upgrade test against real PostgreSQL, rehearsed on a dump of staging.
- **S1.** Single-organisation mode.
- **S2.** Retire tenant hostnames and tenant ingress routes.
- **S3.** Fold the system tenant into the instance. Done in the `FoldSystemTenant` migration:
  - A null `TenantId` now means instance scope everywhere. The system signing CA, SSH CAs, the
    system groups and the instance CAs' groups have no tenant.
  - The instance's CA policy (`RequireKeyCeremony`, `CeremonyRequiredApprovals`,
    `MaxValidityDays`, `ValidityCeilingBehavior`, and the CA-level user quorum) lives on
    `SecurityPolicy`. The migration copies the system tenant's values there as they are. Every
    reader goes through `IEffectivePolicyResolver`, which never answers "no policy".
  - The system tenant's `org-system-*` groups are deleted, and `Tenants.IsSystemTenant` is dropped.
    The tenant foreign keys are `ON DELETE RESTRICT`.
  - The upgrade refuses, rolling back, while open ceremonies name the system tenant, while the
    `org-system-*` groups have members or badge sources, while tenant-wide grants or service
    identities on the system tenant would become instance-wide, or while the instance has more
    than one organisation, whatever the multiple-organisations flag says.
  - New audit records go to the instance chain. Each per-tenant chain is sealed once at control
    start, with its final hash anchored in the instance chain.
  - Instance policy changes by anyone but a system-super go through an `InstancePolicyChange`
    ceremony. The licence counts organisations only.
- **S4.** Remove the isolation-only query filters and fences, and make CA labels and names
  unique across the instance. Done in the `InstanceUniqueCaNames` migration and the code around it:
  - The only global query filters left are soft-delete ones (tenants, CAs, users). There is no
    `ITenantContext`; `TenantResolutionMiddleware` stores the caller's `TenantFence` from
    `GetFenceAsync`, which reads all four grant sources under a worn badge, so the fence equals
    what authorization allows. A capability at system scope makes it instance-wide for that
    capability only (`TenantFence.For`): each endpoint narrows the fence to the capability its
    policy demands, so a system auditor sees every space's audit views but not their operator
    configuration.
  - Every list and read of several spaces' rows applies the fence explicitly; the lists that leaked
    across spaces (whitelists, SSH CA keys and templates, signing and request profiles) are fenced,
    and ACME EAB keys, which no CA owns, are listed only to a fence instance-wide for cert.revoke
    and created or deleted only with cert.revoke at system scope. `SpaceIsolationMatrixTests`
    drives each through the real policies, and again with the policy skipped so the action's own
    fence is tested; `SpaceFenceGuardTests` fails a new read (a GET, or a query POST) that names no
    CA and carries no instance-rank policy until its fence is declared.
  - A write that takes a CA from the body checks the new CA: a signing profile's issuer, a profile's
    or SSH row's CA, an SSH template's key (`CaBindingAccess`), and a protocol configuration's
    signing profile, which must issue from that CA. A CA that has issued keeps its label.
  - A certificate profile is used only by a CA of its own scope (`CertProfileScope`), at issuance
    for every protocol, at CSR submission, on a protocol configuration, a template and an
    inheritance parent.
  - CA labels (ignoring case) and names are unique over all rows, deleted ones included. The
    upgrade refuses while any two CAs collide. Tenant quotas are dropped; group quotas stay.
- **S5.** Simplify ranks to instance, space, CA and operator. Done without a schema change:
  - `ca.manage` at instance scope (no tenant, no CA) is the new controlled tier
    `SystemOperator = 7`, from a direct grant, a role on the account or the system-operator group.
    Before, it conferred no tier, so a lone system admin could make anyone an approver of every
    key ceremony without a ceremony. Granting, removing or deleting it now needs a controlled-user
    ceremony at `SecurityPolicy.UserQuorum`, unless a system-super acts. At each start the control
    role names the accounts that hold it by direct grant or role.
  - The rule is one line: an admin tier dominates every tier inside its scope, an operator tier
    dominates only the identical tier, and super dominates everything. A system operator approves
    only its peers, not a space operator. An undefined level fails closed: it dominates nothing,
    and only super and system admin dominate it.
  - The never-minted CA operator level 1 is removed and stays reserved.
  - One fail-closed covering tier (`ControlledTier.Covering`) replaces the separate total order
    used to classify groups, roles and deletions: super if present, else the tier that dominates
    all the others, else system admin.
  - Ceremony descriptions and the console name the affected scope: a CA, a tenant or the instance.
  - Account administration is a controlled change too. Dominance alone let a peer take over an
    approver: reset its password and MFA, sign in as it and approve their own ceremonies. A
    non-super password reset, MFA reset, or change of username, email, enabled, locked or password
    flags on an account holding any controlled tier opens a `ControlledUserChange` ceremony
    (`ResetPassword`, `ResetMfa`, `UpdateIdentity`) at the covering tier of its holdings. The
    initiator must still dominate every tier the account holds. Disabling and locking are gated
    as well, and refused for the last other active dominator of the scope. The temporary password
    is generated at execute and returned only to the executor, never stored in the ceremony.
  - A CA's key-ceremony quorum, when it comes from a group, comes from the CA's Administrator
    group. It could come from its Operator group, which also holds `ca.manage`.
- **S6.** Rename tenant to space in the schema, API, console and docs. `MintedTierLevel`,
  `MintedTierCaId` and `MintedTierTenantId` are JSON keys in stored ceremony `ParametersJson`, so
  a rename must keep them with `[JsonPropertyName]` or migrate the stored data.
