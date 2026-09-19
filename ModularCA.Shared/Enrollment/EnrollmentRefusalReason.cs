namespace ModularCA.Shared.Enrollment;

/// <summary>
/// Why an enrollment was refused, as a code every protocol shares.
/// </summary>
/// <remarks>
/// <para>
/// Shared so the console explains a refusal once rather than once per protocol. The set is the
/// union of what the five protocols already refuse for, read off their refusal paths rather than
/// invented: EST's identity binding and renewal window, SCEP's challenge password and replay
/// check, CMP's protection and proof-of-possession, MSAE's templates and renewal evidence, ACME's
/// order identifiers and challenge validation.
/// </para>
/// <para>
/// A request that needs an approver is not refused; it is
/// <see cref="EnrollmentOutcome.Pending"/>. A misconfiguration — a profile the configuration names
/// but the database does not have — is not refused either; it is
/// <see cref="EnrollmentOutcome.Failed"/>, because nothing about the request is wrong.
/// </para>
/// </remarks>
public enum EnrollmentRefusalReason
{
    /// <summary>Never returned. The default value, so an unset reason is visible rather than plausible.</summary>
    Unspecified = 0,

    /// <summary>The CA the request addressed does not exist, or is disabled.</summary>
    CaNotFound = 1,

    /// <summary>The CA exists but does not have this protocol enabled.</summary>
    ProtocolDisabledOnCa = 2,

    /// <summary>
    /// No credential was presented where one is required — EST with neither a client certificate
    /// nor HTTP authentication, SCEP with no challenge password, CMP with no message protection.
    /// </summary>
    CredentialMissing = 3,

    /// <summary>
    /// A credential was presented and did not verify: a signature that does not check out, a
    /// challenge password that is unknown, spent or expired, a MAC that does not match.
    /// </summary>
    CredentialInvalid = 4,

    /// <summary>
    /// The credential verified and names someone who may not enroll here: an account without the
    /// enrollment capability on this CA, a signer certificate issued by another CA, an RA
    /// principal not permitted to assert <c>raVerified</c>.
    /// </summary>
    CallerNotAuthorized = 5,

    /// <summary>
    /// The names asked for exceed what the caller's credential vouches for: a CSR subject or SAN
    /// that is not the mTLS client's or the authenticated username's, a SCEP renewal adding a SAN
    /// its signer does not hold, a CMP CertTemplate that is not the signer's, an ACME CSR naming
    /// an identifier the order does not carry, an enrollment token used outside its restriction.
    /// </summary>
    NameNotAuthorizedForCaller = 6,

    /// <summary>The subject DN or the alternative names are refused by the request profile's rules.</summary>
    NameRejectedByProfile = 7,

    /// <summary>The key algorithm, size or curve is not one the profile permits.</summary>
    KeyRejectedByProfile = 8,

    /// <summary>The certificate template the client named is unknown here, or belongs to another CA.</summary>
    TemplateNotAvailable = 9,

    /// <summary>
    /// A renewal names a certificate this service cannot accept as the one being renewed: not
    /// issued here, not signed by its holder, a different subject, or a different template.
    /// </summary>
    RenewalEvidenceInvalid = 10,

    /// <summary>The certificate may be renewed, but not yet — EST's last-30%-of-validity window.</summary>
    RenewalWindowNotOpen = 11,

    /// <summary>The certificate the request leans on has been revoked.</summary>
    CertificateRevoked = 12,

    /// <summary>The certificate the request leans on has expired or is not yet valid.</summary>
    CertificateNotValid = 13,

    /// <summary>Proof of possession of the private key is missing, malformed or does not verify.</summary>
    ProofOfPossessionInvalid = 14,

    /// <summary>The request could not be read: bad encoding, an unparseable CSR, a missing required field.</summary>
    MalformedRequest = 15,

    /// <summary>A transaction id or nonce has been seen before, or the message is outside its freshness window.</summary>
    ReplayDetected = 16,

    /// <summary>
    /// A request the client asks after does not exist, or was submitted by someone else. One code,
    /// because telling those apart tells a stranger what exists.
    /// </summary>
    RequestNotFoundOrNotOwned = 17,

    /// <summary>
    /// The operation does not fit the state the request is in: an ACME order not ready to
    /// finalize, a certificate already revoked, a confirmation already processed.
    /// </summary>
    StateConflict = 18,

    /// <summary>Too many attempts: a rate limit, or a validation retried past its allowance.</summary>
    RateLimited = 19,

    /// <summary>
    /// The evidence a protocol gathers for itself did not hold — an ACME challenge that served the
    /// wrong key authorization, a DNS record that was not there.
    /// </summary>
    ValidationEvidenceInvalid = 20,

    /// <summary>
    /// Something outside this system refuses the issuance — a CAA record that does not authorize
    /// this CA, an address policy that forbids validating against a private address.
    /// </summary>
    ExternalPolicyRefusal = 21,

    /// <summary>The protocol carries an operation this implementation does not offer.</summary>
    UnsupportedOperation = 22,

    /// <summary>
    /// Issuance refused the request on the certificate profile's own rules — a validity window
    /// that resolves to nothing, a key or an extension the profile will not sign. The only refusal
    /// reached after the request row exists, which is why the row is marked rejected rather than
    /// left waiting.
    /// </summary>
    IssuanceRefusedByProfile = 23,
}
