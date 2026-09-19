namespace ModularCA.Shared.Signing;

/// <summary>
/// What a caller is asking the signer to do with a key. The signer's policy is keyed on this
/// together with the kind of key: a CA key signs certificates, CRLs and protocol responses for
/// its own CA; a delegated OCSP responder key signs OCSP responses only; the TSA key signs
/// timestamp tokens only. Ceremony, Backup, Export, Bootstrap and Restore name the contexts under
/// which key generation, import and export are permitted rather than a signature operation.
/// </summary>
public enum SigningPurpose
{
    /// <summary>Sign an X.509 certificate.</summary>
    Certificate,

    /// <summary>Sign a certificate revocation list, full or delta.</summary>
    Crl,

    /// <summary>Sign an OCSP response.</summary>
    Ocsp,

    /// <summary>Sign or decrypt a SCEP envelope.</summary>
    Scep,

    /// <summary>Sign a CMP response.</summary>
    Cmp,

    /// <summary>Sign a timestamp token.</summary>
    Tsa,

    /// <summary>A key ceremony: generation, import or cross-certification under quorum.</summary>
    Ceremony,

    /// <summary>A backup export of the keystore.</summary>
    Backup,

    /// <summary>Export of an end-entity key to its holder.</summary>
    Export,

    /// <summary>Initial bootstrap of the node, before any ceremony exists.</summary>
    Bootstrap,

    /// <summary>Restore of a backup: keystore files imported through the signer as the archive carries them.</summary>
    Restore,

    /// <summary>
    /// A delegated key of an existing CA: its OCSP responder, timestamp or CMP signer. Generated
    /// and committed without a ceremony, held to the CA and tenant named, and never committed to
    /// a CA certificate; reissuing a responder is an operator's action, not a ceremony.
    /// </summary>
    Infrastructure,
}
