namespace ModularCA.Shared.Signing;

/// <summary>
/// What a secret the signer wraps actually is. This is not a key reference: a caller of
/// <see cref="ISigningService.WrapSecretAsync"/> never chooses which key wraps for it, it says
/// what the secret is and the signer decides. The signer's wrap policy is a table over this and
/// <see cref="SigningPurpose"/>, so a caller permitted to unwrap one kind cannot unwrap another,
/// and the kind is carried in the wrapped blob's associated data so the separation holds
/// cryptographically as well as by policy.
/// </summary>
public enum SecretKind
{
    /// <summary>
    /// The CMP PBMAC shared secret of an enrollment token. Password-based message authentication
    /// is symmetric, so the authority has to recover this one to verify a client's protection.
    /// </summary>
    CmpSharedSecret = 1,

    /// <summary>
    /// A requester's private key held on its certificate request row between the request and the
    /// single delivery of the PKCS#12. Not adopted yet; see the design document.
    /// </summary>
    HeldPrivateKey = 2,

    /// <summary>
    /// The symmetric key of a Kerberos realm, used by the MSAE acceptor. Not adopted yet, and no
    /// <see cref="SigningPurpose"/> may wrap or unwrap it, because it is read once per
    /// authentication and the caching question has to be answered before the signer is in that
    /// path; see the design document.
    /// </summary>
    KerberosRealmKey = 3,

    /// <summary>
    /// A bundle of node configuration secrets a backup archive carries: the Data Protection key
    /// ring, and the SSH CA keys until they have a keystore of their own. Wrapped under
    /// <see cref="SigningPurpose.Backup"/> and unwrapped under <see cref="SigningPurpose.Restore"/>
    /// only, so opening one needs the keystore and its passphrases as well as the archive key.
    /// </summary>
    BackupConfigSecret = 4,

    /// <summary>
    /// The value of a secret setting kept in the settings store: the JWT secret, the LDAP bind
    /// password, the mail credentials, the webhook endpoints. Wrapped and unwrapped under
    /// <see cref="SigningPurpose.Configuration"/> only, and always bound to the setting's key
    /// (<see cref="ISigningService.WrapBoundSecretAsync"/>), so a blob moved to another
    /// setting's row does not unwrap there.
    /// </summary>
    SettingSecret = 5,
}
