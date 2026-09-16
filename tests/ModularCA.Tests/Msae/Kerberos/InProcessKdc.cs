using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;
using Kerberos.NET.Transport;

namespace ModularCA.Tests.Msae.Kerberos;

/// <summary>
/// One Active Directory forest, in memory: a KDC for a realm with a krbtgt, a service account
/// holding the enrollment SPN, and whatever users and machines a test adds. A client obtains
/// real AS and TGS tickets from it through an in-process transport, so the acceptor is tested
/// with the same bytes a Windows client would send, without a socket or a domain.
/// </summary>
public sealed class InProcessKdc
{
    public const string ServicePrincipal = "HTTP/ca4.maroongang.net";

    private readonly KdcServer _kdc;
    private readonly ConcurrentDictionary<string, Principal> _principals = new(StringComparer.OrdinalIgnoreCase);

    public string Realm { get; }
    public string DnsDomain => Realm.ToLowerInvariant();
    /// <summary>The service account's long-term key: what the tenant would import into ModularCA.</summary>
    public KerberosKey ServiceKey { get; }

    public InProcessKdc(string realm, string servicePassword = "Svc-P@ssw0rd-1")
    {
        Realm = realm.ToUpperInvariant();
        ServiceKey = Key("svc-enroll", servicePassword, SaltType.ActiveDirectoryUser);
        _principals["krbtgt"] = new Principal($"krbtgt/{Realm}", Key("krbtgt", Guid.NewGuid().ToString("N"), SaltType.ActiveDirectoryUser), PrincipalType.Service);
        _principals[ServicePrincipal] = new Principal(ServicePrincipal, ServiceKey, PrincipalType.Service);

        var options = new KdcServerOptions
        {
            DefaultRealm = Realm,
            RealmLocator = _ => new RealmService(this),
            Configuration = Krb5Config.Kdc(),
        };
        _kdc = new KdcServer(options);
    }

    /// <summary>Adds a user or machine account (name ending in <c>$</c>) with a password.</summary>
    public void AddAccount(string name, string password)
        => _principals[name] = new Principal(name, Key(name, password, SaltType.ActiveDirectoryUser), PrincipalType.User);

    /// <summary>Authenticates as <paramref name="name"/> and returns the GSS-API bytes of a service ticket for the enrollment SPN.</summary>
    public async Task<byte[]> ServiceTicketAsync(string name, string password)
    {
        var config = Krb5Config.Default();
        config.Defaults.DefaultRealm = Realm;
        config.Defaults.DnsLookupKdc = false;

        using var client = new KerberosClient(config, null, new IKerberosTransport[] { new InProcessTransport(_kdc) })
        {
            CacheInMemory = true,
            CacheServiceTickets = false,
        };
        await client.Authenticate(new KerberosPasswordCredential(name, password, Realm));
        var apReq = await client.GetServiceTicket(ServicePrincipal, ApOptions.MutualRequired);
        return apReq.EncodeGssApi().ToArray();
    }

    private KerberosKey Key(string account, string password, SaltType saltType)
        => new(password, new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { account }), etype: EncryptionType.AES256_CTS_HMAC_SHA1_96, saltType: saltType);

    private sealed record Principal(string Name, KerberosKey Key, PrincipalType Type);

    /// <summary>Routes client messages straight into the KDC.</summary>
    private sealed class InProcessTransport : KerberosTransportBase
    {
        private readonly KdcServer kdc;

        public InProcessTransport(KdcServer kdc) : base(null)
        {
            this.kdc = kdc;
            Enabled = true;
        }

        public override Task<ReadOnlyMemory<byte>> SendMessage(string domain, ReadOnlyMemory<byte> encoded, CancellationToken cancellation = default)
            => kdc.ProcessMessage(encoded);

        public override Task<ReadOnlyMemory<byte>> SendMessageChangePassword(string domain, ReadOnlyMemory<byte> encoded, CancellationToken cancellation = default)
            => throw new NotSupportedException();
    }

    private sealed class RealmService(InProcessKdc owner) : IRealmService
    {
        public string Name => owner.Realm;
        public IRealmSettings Settings { get; } = new RealmSettings();
        public IPrincipalService Principals { get; } = new PrincipalService(owner);
        public ITrustedRealmService TrustedRealms { get; } = new NoTrustedRealms();
        public Krb5Config Configuration { get; } = Krb5Config.Kdc();
        public DateTimeOffset Now() => DateTimeOffset.UtcNow;
    }

    private sealed class RealmSettings : IRealmSettings
    {
        public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);
        public TimeSpan SessionLifetime => TimeSpan.FromHours(10);
        public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);
        public KerberosCompatibilityFlags Compatibility => KerberosCompatibilityFlags.IsolateRealmsConsistently | KerberosCompatibilityFlags.EnableSpecCompliantCNameHandling;
    }

    private sealed class NoTrustedRealms : ITrustedRealmService
    {
        public IRealmReferral ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context) => null!;
    }

    private sealed class PrincipalService(InProcessKdc owner) : IPrincipalService
    {
        public IKerberosPrincipal Find(KrbPrincipalName principalName, string? realm = null)
        {
            var name = principalName.FullyQualifiedName;
            var at = name.IndexOf('@');
            if (at >= 0) name = name[..at];
            if (name.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase)) name = "krbtgt";
            return owner._principals.TryGetValue(name, out var p) ? new KdcPrincipal(owner, p) : null!;
        }

        public Task<IKerberosPrincipal> FindAsync(KrbPrincipalName principalName, string? realm = null) => Task.FromResult(Find(principalName, realm));
        public X509Certificate2 RetrieveKdcCertificate() => throw new NotSupportedException();
        public IExchangeKey RetrieveKeyCache(KeyAgreementAlgorithm algorithm) => null!;
        public IExchangeKey CacheKey(IExchangeKey key) => key;
    }

    private sealed class KdcPrincipal(InProcessKdc owner, Principal principal) : IKerberosPrincipal
    {
        private static readonly SecurityIdentifier DomainSid = new(IdentifierAuthority.NTAuthority, new uint[] { 21, 1000, 2000, 3000 }, 0);

        public string PrincipalName => principal.Name;
        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; } = new[] { PaDataType.PA_ENC_TIMESTAMP };
        public SupportedEncryptionTypes SupportedEncryptionTypes => SupportedEncryptionTypes.Aes256CtsHmacSha196 | SupportedEncryptionTypes.Aes128CtsHmacSha196;
        public PrincipalType Type => principal.Type;
        public DateTimeOffset? Expires => DateTimeOffset.UtcNow.AddYears(10);
        public void Validate(X509Certificate2Collection certificates) { }
        public KerberosKey RetrieveLongTermCredential() => principal.Key;
        public KerberosKey RetrieveLongTermCredential(EncryptionType etype) => principal.Key;

        public PrivilegedAttributeCertificate GeneratePac() => new()
        {
            LogonInfo = new PacLogonInfo
            {
                DomainName = owner.Realm,
                UserName = principal.Name,
                UserDisplayName = principal.Name,
                DomainSid = DomainSid,
                UserSid = new SecurityIdentifier(DomainSid, 1105),
                GroupSid = new SecurityIdentifier(DomainSid, 513),
                LogonTime = DateTimeOffset.UtcNow,
                ServerName = "DC01",
                UserAccountControl = principal.Name.EndsWith('$') ? UserAccountControlFlags.ADS_UF_WORKSTATION_TRUST_ACCOUNT : UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                UserFlags = UserFlags.LOGON_WINLOGON,
            },
        };
    }
}

/// <summary>A replay cache for one test: remembers every authenticator it has seen.</summary>
public sealed class InMemoryReplayValidator : ITicketReplayValidator
{
    private readonly HashSet<string> _seen = new();
    public Task<bool> Add(TicketCacheEntry entry) => Task.FromResult(_seen.Add(entry.Computed));
    public Task<bool> Contains(TicketCacheEntry entry) => Task.FromResult(_seen.Contains(entry.Computed));
}
