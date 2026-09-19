# The enrollment protocol contract

Status: design, 2026-09-17. Follows the role separation in
[signer-separation.md](signer-separation.md); this is the enrollment role's internal shape.

## Why

Five protocols issue certificates: ACME, EST, SCEP, CMP and MSAE. They speak entirely different
wire formats and authenticate in entirely different ways, and that part is irreducible. What they
do between parsing and responding is the same work every time: find the CA, check the protocol is
enabled on it, authorize the caller, resolve the effective profiles, validate the subject and
alternative names, record a request, issue or take it under submission, and audit the outcome.

Today each protocol wires that middle by hand, in its own order, with its own error handling and
its own audit calls. The pieces are shared (`IEnrollmentAuthorizationService`,
`IProfileResolutionService`, `ICertificateIssuanceService`), but the sequence is not, so the same
rule can be applied in five places and forgotten in a sixth. Adding MSAE meant reproducing that
sequence again, and the approval-gated path had to be discovered separately for it after EST
already had one.

A contract makes the middle one implementation. A new protocol then supplies only what is
genuinely its own: how to parse its request, how to authenticate it, and how to render the
answer.

## What is protocol-specific and what is not

| Step | Owner |
|---|---|
| Parse the wire format into a request | protocol |
| Authenticate the caller (JWS, client certificate, PKCS#7 signer, Kerberos, shared secret) | protocol |
| Resolve the CA the request addresses | shared |
| Refuse when the protocol is disabled on that CA | shared |
| Authorize the caller against that CA | shared |
| Resolve the effective request and certificate profiles | shared |
| Validate subject and alternative names against the profile | shared |
| Apply the CA's protocol configuration (default profiles, allowed modes) | shared |
| Record the request, with any extensions the protocol asks for | shared |
| Issue, or take under submission when the profile requires approval | shared |
| Audit the outcome, accepted or refused | shared |
| Render the response or the refusal in the wire format | protocol |

## The contract

Two interfaces. The adapter is what a protocol implements; the pipeline is what it calls.

```
interface IEnrollmentProtocol
{
    string Name { get; }                       // "ACME", "EST", "SCEP", "CMP", "MSAE"
    EnrollmentCapabilities Capabilities { get; }
}
```

`EnrollmentCapabilities` is a flag set the console and the readiness checks can read rather than
infer: enroll, re-enroll, renew, poll for a pending request, collect, revoke, server-side key
generation. It is what lets a protocol page say what a protocol can do without a lookup table
that drifts.

```
interface IEnrollmentPipeline
{
    Task<EnrollmentOutcome> SubmitAsync(EnrollmentSubmission submission, CancellationToken ct);
    Task<EnrollmentOutcome> PollAsync(EnrollmentPoll poll, CancellationToken ct);
}
```

`EnrollmentSubmission` is the normalized request every protocol produces:

- the protocol name and the CA it addresses, by label or by default
- the authenticated caller: a principal, how it was authenticated, and whether the protocol
  considers it verified
- the certification request: the CSR, or a subject plus alternative names plus a public key when
  the protocol builds one
- a profile hint: the template or profile the client named, if any
- requested validity, requested extensions, and renewal evidence when the request renews
- an opaque per-protocol correlation value carried into the audit row

`EnrollmentOutcome` is a closed set the protocol renders: issued with the certificate and chain,
pending with a request identifier, refused with a reason code and a sentence, or failed. Reason
codes are shared so that the console explains a refusal once for every protocol rather than per
protocol, which is what the MSAE audit explainer already does for one of them.

## What this is not

It is not a rewrite. The five implementations are proven, MSAE over weeks of live lab work, and
their wire handling stays exactly as it is. The change is that the middle of each moves behind the
pipeline and the protocol keeps its parsing, its authentication and its rendering. No wire
behaviour changes, and the existing tests are the guard: every protocol test must pass unchanged
at every step.

It is not a runtime plugin system. Protocols are compiled in and registered; the contract is a
design boundary, not a loader.

## ACME is the exception worth stating

ACME is not a request and a response. It is accounts, orders, authorizations, challenges and
nonces, a state machine the other four do not have. Only its finalize step maps onto this
contract, and that is the only part that should move behind the pipeline. The order and challenge
machinery stays ACME's own. A contract that tried to generalise it would describe nothing.

## Order of work

1. The types: `EnrollmentSubmission`, `EnrollmentOutcome`, `EnrollmentCapabilities`, the shared
   refusal reasons. No behaviour.
2. The pipeline, implemented by lifting the middle out of the protocol that is clearest about it.
   EST is the candidate: it already resolves profiles, authorizes and has an approval path.
3. Migrate EST to it, tests unchanged.
4. Migrate MSAE, then CMP, then SCEP, then ACME's finalize. One protocol per commit, tests green
   at each.
5. Delete the duplicated middles.
6. An architecture test that fails if a protocol service calls issuance, profile resolution or
   enrollment authorization directly instead of through the pipeline. That is what keeps the
   contract true after this work ends.

## Open questions for implementation

- Whether the pipeline owns the audit row or the protocol does. The audit tables are per protocol
  today (`AuditMsae` and others) and that is worth keeping; the pipeline can write the shared
  fields and hand the protocol its own.
- Whether pending and collect are one concept across protocols. MSAE polls by status query, EST
  refuses with a retry, CMP has its own; the outcome type covers all three, but the poll side may
  not generalise as cleanly.
- Where per-CA protocol configuration is read. Each protocol reads it today; the pipeline should,
  but the shape differs per protocol and the columns are protocol-prefixed.
