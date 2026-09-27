# The instance is the tenant

Status: proposed 2026-09-26. No deployment runs more than one non-system tenant, so nothing
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

The schema changes in steps 3 and 4 follow the project rule: the single `InitialCreate` per
context is regenerated, and no migration is added.
