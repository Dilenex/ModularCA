using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Shared.Enrollment;

/// <summary>
/// How a protocol proved who is asking. Recorded on the audit row and, for some protocols, read
/// by the shared authorization step.
/// </summary>
public enum EnrollmentAuthMethod
{
    /// <summary>No credential was presented. Never sufficient on its own.</summary>
    None = 0,

    /// <summary>A TLS client certificate — EST mTLS.</summary>
    ClientCertificate = 1,

    /// <summary>An HTTP credential: Basic, or a bearer token naming an account.</summary>
    HttpCredential = 2,

    /// <summary>Message-level protection the protocol verified itself — a CMP signature, a SCEP CMS signer, an ACME JWS.</summary>
    MessageSignature = 3,

    /// <summary>A shared secret carried in the request — a SCEP challenge password, an enrollment token.</summary>
    SharedSecret = 4,

    /// <summary>A Kerberos ticket — MSAE under a keytab.</summary>
    Kerberos = 5,
}

/// <summary>
/// The authenticated caller a protocol hands to the pipeline: who is asking, how that was proven,
/// and whether the protocol considers the proof good.
/// </summary>
/// <remarks>
/// Authentication is the protocol's own work and has already happened by the time a caller
/// reaches here. <see cref="IsVerified"/> is the protocol's verdict on its own credential, not a
/// second opinion the pipeline forms; the pipeline turns it into an authorization question about
/// the CA the request addresses.
/// </remarks>
/// <param name="Principal">
/// The caller as the audit row should name it — <c>mtls:CN=printer1</c>, <c>basic:alice</c>,
/// <c>host/pc1@EXAMPLE.COM</c>. Null when the protocol has nothing to name.
/// </param>
/// <param name="AuthMethod">How <paramref name="Principal"/> was proven.</param>
/// <param name="IsVerified">Whether the protocol accepted the credential it was given.</param>
/// <param name="Username">
/// The account behind the credential, when it names one. This is what membership on the target CA
/// is checked against: a password proves identity, not entitlement.
/// </param>
/// <param name="ClientCertificate">
/// The TLS client certificate, when one was presented. Whether it chains to the target CA is the
/// protocol's own check, made before the caller gets here.
/// </param>
public sealed record EnrollmentCaller(
    string? Principal,
    EnrollmentAuthMethod AuthMethod,
    bool IsVerified,
    string? Username = null,
    X509Certificate2? ClientCertificate = null)
{
    /// <summary>An unauthenticated caller: nothing presented, nothing proven.</summary>
    public static EnrollmentCaller Anonymous { get; } =
        new(null, EnrollmentAuthMethod.None, IsVerified: false);
}
