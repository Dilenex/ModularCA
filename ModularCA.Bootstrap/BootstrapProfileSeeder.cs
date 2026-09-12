using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using System.Text.Json;

namespace ModularCA.Bootstrap;

/// <summary>
/// Seeds certificate profiles, signing profiles, OIDs, request profiles,
/// protocol configurations, service URLs, feature flags, password policies,
/// notification preferences, and the initial superadmin user into the database.
/// </summary>
public static class BootstrapProfileSeeder
{
    /// <summary>
    /// Loads standard and extended OID seed data from the parsed YAML config into the database.
    /// Skips loading if OIDs are already present.
    /// </summary>
    public static void LoadOidsToDb(ModularCADbContext db, YamlOIDLoader.OIDSeedConfig OIDConfig)
    {
        if (db.OIDOptions.Any())
        {
            Console.WriteLine("✓ OIDs already loaded into the database.");
            return;
        }

        var standardOids = OIDConfig.OID.StandardKeyUsage!;

        for (var oid = 0; oid < standardOids.Count; oid++)
        {
            db.OIDOptions.Add(new OIDOptionEntity
            {
                OID = standardOids.Values.ToList()[oid],
                FriendlyName = standardOids.Keys.ToList()[oid],
                IsDefaultEntry = true,
                KeyUsage = "Standard"
            });

            db.SaveChanges();
        }

        var extendedOids = OIDConfig.OID.ExtendedKeyUsage!;

        for (var oid = 0; oid < extendedOids.Count; oid++)
        {
            db.OIDOptions.Add(new OIDOptionEntity
            {
                OID = extendedOids.Values.ToList()[oid],
                FriendlyName = extendedOids.Keys.ToList()[oid],
                IsDefaultEntry = true,
                KeyUsage = "Extended"
            });

            db.SaveChanges();
        }

        Console.WriteLine("✓ OIDs loaded into the database.");
    }

    /// <summary>
    /// Returns the list of friendly names for the requested standard key-usage OIDs
    /// that exist in the database.
    /// </summary>
    public static List<string> SetupAllowedStandardOids(string[] allowedStandardOids, ModularCADbContext db)
    {
        // Resolves by friendly name OR OID, ignoring case and separators. This was an ordinal
        // HashSet.Contains against the catalog's FriendlyName, and its callers pass display names
        // ("Digital Signature") while the catalog stores camelCase ("digitalSignature") — zero
        // overlap, so every call returned an empty list and the root CA was issued with no
        // KeyUsage extension. See UsageCatalogResolver for the full history.
        var catalog = db.OIDOptions
            .Where(o => o.KeyUsage == "Standard")
            .Select(o => new { o.OID, o.FriendlyName })
            .ToList()
            .Select(o => ((string?)o.OID, (string?)o.FriendlyName));

        // The certificate builder parses friendly names for KeyUsage, so return those.
        var lookup = UsageCatalogResolver.BuildLookup(catalog, e => e.FriendlyName!);

        var resolved = allowedStandardOids
            .Select(u => UsageCatalogResolver.Resolve(lookup, u))
            .Where(n => n != null)
            .Select(n => n!)
            .Distinct()
            .ToList();

        WarnOnUnresolved(allowedStandardOids, lookup, "standard key usage");
        return resolved;
    }

    /// <summary>
    /// Bootstrap seeds the profiles a CA issues from, so a usage silently vanishing here is
    /// permanent for the life of the installation. Say so loudly rather than seeding an empty
    /// list — the original defect was invisible precisely because nothing complained.
    /// </summary>
    private static void WarnOnUnresolved(string[] requested, Dictionary<string, string> lookup, string kind)
    {
        var unresolved = requested
            .Where(u => UsageCatalogResolver.Resolve(lookup, u) == null)
            .ToList();
        if (unresolved.Count == 0) return;

        Console.WriteLine(
            $"(!) {kind}(s) not found in the OID catalog and omitted from the seeded profile: " +
            string.Join(", ", unresolved));
        Console.WriteLine(
            "    Check config/OIDSeed.yaml, or the built-in defaults in YamlOIDLoader if it is absent.");
    }

    /// <summary>
    /// Returns a JSON-serialized list of friendly names for the requested standard key-usage OIDs.
    /// </summary>
    public static string SetupAllowedStandardOidsJson(string[] allowedStandardOids, ModularCADbContext db)
    {
        var allowedStandard = SetupAllowedStandardOids(allowedStandardOids, db);
        var allowedStandardJson = JsonSerializer.Serialize(allowedStandard);
        return allowedStandardJson;
    }

    /// <summary>
    /// Returns the list of OID values for the requested extended key-usage OIDs
    /// that exist in the database.
    /// </summary>
    public static List<string> SetupAllowedExtendedOids(string[] allowedExtendedOids, ModularCADbContext db)
    {
        var catalog = db.OIDOptions
            .Where(o => o.KeyUsage == "Extended")
            .Select(o => new { o.OID, o.FriendlyName })
            .ToList()
            .Select(o => ((string?)o.OID, (string?)o.FriendlyName));

        // The certificate builder emits OIDs for ExtendedKeyUsage, so return those.
        var lookup = UsageCatalogResolver.BuildLookup(catalog, e => e.Oid!);

        var resolved = allowedExtendedOids
            .Select(u => UsageCatalogResolver.Resolve(lookup, u))
            .Where(o => o != null)
            .Select(o => o!)
            .Distinct()
            .ToList();

        WarnOnUnresolved(allowedExtendedOids, lookup, "extended key usage");
        return resolved;
    }

    /// <summary>
    /// Returns a JSON-serialized list of OID values for the requested extended key-usage OIDs.
    /// </summary>
    public static string SetupAllowedExtendedOidsJson(string[] allowedExtendedOids, ModularCADbContext db)
    {
        var allowedExtended = SetupAllowedExtendedOids(allowedExtendedOids, db);
        var allowedExtendedJson = JsonSerializer.Serialize(allowedExtended);
        return allowedExtendedJson;
    }

    /// <summary>
    /// Creates a certificate profile entity with allowed key algorithms, key sizes,
    /// signature algorithms, key usages, extended key usages, and validity bounds.
    /// </summary>
    public static void CreateCertProfile(ModularCADbContext db, string certProfileName, string certProfileDescription,
        string[] keyUsage, string[] extendedKeyUsage, bool canBeDeleted, bool isCaProfile,
        string allowedKeyAlgorithmsJson, string allowedKeySizesJson, string allowedSignatureAlgorithmsJson,
        string validityPeriodMin, string validityPeriodMax)
    {

        if (db.CertProfiles.Any(c => c.Name == certProfileName))
        {
            throw new InvalidOperationException($"A certificate profile with the name '{certProfileName}' already exists.");
        }
        var StandardKeyOidsJson = SetupAllowedStandardOidsJson(keyUsage, db);
        var ExtendedKeyOidsJson = SetupAllowedExtendedOidsJson(extendedKeyUsage, db);
        var certProfile = new CertProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = certProfileName,
            IsCaProfile = isCaProfile,
            Description = certProfileDescription,
            KeyUsages = StandardKeyOidsJson,
            ExtendedKeyUsages = ExtendedKeyOidsJson,
            AllowedKeyAlgorithms = allowedKeyAlgorithmsJson,
            AllowedKeySizes = allowedKeySizesJson,
            AllowedSignatureAlgorithms = allowedSignatureAlgorithmsJson,
            ValidityPeriodMin = validityPeriodMin,
            ValidityPeriodMax = validityPeriodMax,
            CreatedAt = DateTime.UtcNow,
            CanBeDeleted = canBeDeleted
        };
        db.CertProfiles.Add(certProfile);
        db.SaveChanges();
        Console.WriteLine($"✓ Certificate profile '{certProfile.Name}' inserted into database.");
    }

    /// <summary>
    /// Creates a signing profile entity with allowed algorithms, allowed EKUs, and an optional issuer.
    /// After creation, link to a cert profile via <see cref="LinkCertProfileToSigningProfile"/>.
    /// </summary>
    public static void CreateSigningProfile(ModularCADbContext db, string signingProfileName, string signingProfileDescription,
        CertificateEntity? issuer, string allowedAlgorithmsJson, string allowedEKUsJson)
    {
        if (db.SigningProfiles.Any(sp => sp.Name == signingProfileName))
        {
            throw new InvalidOperationException($"A signing profile with the name '{signingProfileName}' already exists.");
        }

        var signingProfile = new SigningProfileEntity
        {
            Name = signingProfileName,
            Description = signingProfileDescription,
            AllowedAlgorithms = allowedAlgorithmsJson,
            AllowedEKUs = allowedEKUsJson,
            Issuer = issuer!,
            IssuerId = issuer?.CertificateId
        };

        db.SigningProfiles.Add(signingProfile);
        db.SaveChanges();
        Console.WriteLine($"✓ Signing profile '{signingProfile.Name}' inserted into database.");
    }

    /// <summary>
    /// Inserts a row into the AllowedCertProfileSigningProfiles join table,
    /// linking a cert profile to a signing profile for authorized use.
    /// </summary>
    public static void LinkCertProfileToSigningProfile(ModularCADbContext db, CertProfileEntity certProfile, SigningProfileEntity signingProfile)
    {
        db.AllowedCertProfileSigningProfiles.Add(new AllowedCertProfileSigningProfileEntity
        {
            CertProfileId = certProfile.Id,
            SigningProfileId = signingProfile.Id
        });
        db.SaveChanges();
        Console.WriteLine($"✓ Linked cert profile '{certProfile.Name}' to signing profile '{signingProfile.Name}'.");
    }

    /// <summary>
    /// Retrieves a signing profile entity by name from the database.
    /// Throws if not found.
    /// </summary>
    public static SigningProfileEntity GetSigningProfileFromDb(ModularCADbContext db, string signingProfileName)
    {
        var signingProfile = db.SigningProfiles
            .FirstOrDefault(p => p.Name == signingProfileName);
        return signingProfile ?? throw new InvalidOperationException($"Signing profile '{signingProfileName}' not found.");
    }

    /// <summary>
    /// Retrieves a certificate profile entity by name from the database.
    /// Throws if not found.
    /// </summary>
    public static CertProfileEntity GetCertProfileFromDb(ModularCADbContext db, string certProfileName)
    {
        var certProfile = db.CertProfiles
            .FirstOrDefault(p => p.Name == certProfileName);
        return certProfile ?? throw new InvalidOperationException($"Cert profile '{certProfileName}' not found.");
    }

    /// <summary>
    /// Seeds the five default request profiles (Web Server, Enterprise Server, MDM Device,
    /// Enterprise User, Code Signing) with best-practice DN/SAN rules.
    /// Returns a dictionary keyed by profile short name for protocol config assignment.
    /// </summary>
    public static Dictionary<string, RequestProfileEntity> SeedDefaultRequestProfiles(ModularCADbContext db)
    {
        if (db.RequestProfiles.Any())
        {
            Console.WriteLine("✓ Request profiles already seeded.");
            return db.RequestProfiles.ToDictionary(
                rp => rp.Name.Contains("Web Server") ? "WebServer"
                    : rp.Name.Contains("Enterprise Server") ? "EnterpriseServer"
                    : rp.Name.Contains("MDM") ? "MdmDevice"
                    : rp.Name.Contains("Enterprise User") ? "EnterpriseUser"
                    : rp.Name.Contains("Code Signing") ? "CodeSigning"
                    : rp.Name,
                rp => rp);
        }

        var profiles = new Dictionary<string, RequestProfileEntity>();

        // 1. Web Server (ACME/EST) — public TLS, auto-approve
        var webServer = new RequestProfileEntity
        {
            Name = "Web Server (ACME)",
            Description = "Public-facing TLS certificates. CN must be a valid domain. SANs required. Auto-approved via ACME challenges.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", Regex = @"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", MaxLength = 64 },
                new() { Field = "O", Requirement = "Forbidden" },
                new() { Field = "OU", Requirement = "Forbidden" },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = new[] { "DNS", "IP" },
                required = true,
                rules = new Dictionary<string, object>
                {
                    ["DNS"] = new { regex = (string?)null, maxCount = 100 },
                    ["IP"] = new { regex = (string?)null, maxCount = 10 },
                }
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = false,
        };
        db.RequestProfiles.Add(webServer);
        profiles["WebServer"] = webServer;

        // 1b. Web TLS (Internal) — management-UI Web TLS cert issued during bootstrap
        // and reissued via the admin UI. Distinct from "Web Server (ACME)" because the
        // operator's own root CA is the validation authority (not domain-control proof),
        // so organizational identity fields are legitimately permissible. CABF BR §7.1.4.2.2
        // does not apply: this isn't a DV cert from a public CA. CN may be a hostname OR an
        // IP literal (first-install / lab deployments without DNS), so no regex constraint
        // on CN.
        var webTlsInternal = new RequestProfileEntity
        {
            Name = "Web TLS (Internal)",
            Description = "Management UI Web TLS certificate (bootstrap + admin reissue). Permits organization fields because the issuing CA is the operator's own root, not a public DV CA.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", MaxLength = 64 },
                new() { Field = "O", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "OU", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "L", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "ST", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "C", Requirement = "Optional", MaxLength = 2 },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = new[] { "DNS", "IP" },
                required = true,
                rules = new Dictionary<string, object>
                {
                    ["DNS"] = new { regex = (string?)null, maxCount = 100 },
                    ["IP"] = new { regex = (string?)null, maxCount = 10 },
                }
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = false,
        };
        db.RequestProfiles.Add(webTlsInternal);
        profiles["WebTlsInternal"] = webTlsInternal;

        // 2. Enterprise Server (EST) — internal TLS with org fields
        var enterpriseServer = new RequestProfileEntity
        {
            Name = "Enterprise Server (EST)",
            Description = "Internal server certificates with organization fields. SANs required. Auto-approved via EST authentication.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", MaxLength = 64 },
                new() { Field = "O", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "OU", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "L", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "ST", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "C", Requirement = "Optional", MaxLength = 2 },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = new[] { "DNS", "IP" },
                required = true,
                rules = new Dictionary<string, object>
                {
                    ["DNS"] = new { regex = (string?)null, maxCount = 50 },
                    ["IP"] = new { regex = (string?)null, maxCount = 10 },
                }
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = false,
        };
        db.RequestProfiles.Add(enterpriseServer);
        profiles["EnterpriseServer"] = enterpriseServer;

        // 3. MDM Device (SCEP) — locked down for mobile/IoT
        var mdmDevice = new RequestProfileEntity
        {
            Name = "MDM Device (SCEP)",
            Description = "Mobile and IoT device certificates. Organization fields fixed by policy. Auto-approved via SCEP challenge password.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", MaxLength = 64 },
                new() { Field = "O", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "OU", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "C", Requirement = "Optional", MaxLength = 2 },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = new[] { "DNS" },
                required = false,
                rules = new Dictionary<string, object>
                {
                    ["DNS"] = new { regex = (string?)null, maxCount = 5 },
                }
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = false,
        };
        db.RequestProfiles.Add(mdmDevice);
        profiles["MdmDevice"] = mdmDevice;

        // 4. Enterprise User (CMP) — manual approval required
        var enterpriseUser = new RequestProfileEntity
        {
            Name = "Enterprise User (CMP)",
            Description = "User certificates for authentication and email. Requires manual admin approval before issuance.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", MaxLength = 64 },
                new() { Field = "O", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "OU", Requirement = "Optional", MaxLength = 64 },
                new() { Field = "C", Requirement = "Optional", MaxLength = 2 },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = new[] { "Email" },
                required = false,
                rules = new Dictionary<string, object>
                {
                    ["Email"] = new { regex = (string?)null, maxCount = 3 },
                }
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = true,
        };
        db.RequestProfiles.Add(enterpriseUser);
        profiles["EnterpriseUser"] = enterpriseUser;

        // 5. Code Signing — strict, always reviewed
        var codeSigning = new RequestProfileEntity
        {
            Name = "Code Signing",
            Description = "Code signing certificates. Requires manual admin approval. No SANs.",
            SubjectDnRules = JsonSerializer.Serialize(new SubjectDnFieldRule[]
            {
                new() { Field = "CN", Requirement = "Required", MaxLength = 64 },
                new() { Field = "O", Requirement = "Required", MaxLength = 64 },
                new() { Field = "C", Requirement = "Required", MaxLength = 2 },
            }),
            SanRules = JsonSerializer.Serialize(new
            {
                allowedTypes = Array.Empty<string>(),
                required = false,
                rules = new Dictionary<string, object>()
            }),
            AllowedCertProfileIds = "[]",
            RequireApproval = true,
        };
        db.RequestProfiles.Add(codeSigning);
        profiles["CodeSigning"] = codeSigning;

        db.SaveChanges();
        Console.WriteLine($"✓ {profiles.Count} default request profiles seeded (Web Server, Enterprise Server, MDM Device, Enterprise User, Code Signing).");
        return profiles;
    }

    /// <summary>
    /// Seeds per-CA protocol configuration records (ACME, EST, SCEP, CMP, OCSP)
    /// so the multi-CA routing infrastructure works out of the box after bootstrap.
    /// </summary>
    public static void SeedProtocolConfigs(ModularCADbContext db, CertificateAuthorityEntity ca,
        SigningProfileEntity signingProfile, CertProfileEntity certProfile,
        Dictionary<string, RequestProfileEntity>? requestProfiles = null)
    {
        var protocols = new[] { "ACME", "EST", "SCEP", "CMP", "OCSP" };
        foreach (var protocol in protocols)
        {
            Guid? requestProfileId = null;
            if (requestProfiles != null)
            {
                var key = protocol switch
                {
                    "ACME" => "WebServer",
                    "EST" => "EnterpriseServer",
                    "SCEP" => "MdmDevice",
                    "CMP" => "EnterpriseUser",
                    _ => null
                };
                if (key != null && requestProfiles.TryGetValue(key, out var rp))
                    requestProfileId = rp.Id;
            }

            var config = new CaProtocolConfigEntity
            {
                CaId = ca.Id,
                Protocol = protocol,
                IsEnabled = true,
                SigningProfileId = signingProfile.Id,
                CertProfileId = certProfile.Id,
                RequestProfileId = requestProfileId
            };
            db.CaProtocolConfigs.Add(config);
        }
        db.SaveChanges();
        Console.WriteLine($"✓ Protocol configs seeded for CA '{ca.Name}' (ACME, EST, SCEP, CMP, OCSP).");
    }

    /// <summary>
    /// Seeds per-CA protocol configuration records for a system-only CA with every
    /// protocol hardcoded <c>IsEnabled=false</c> and <c>IsPublicVisible=false</c>. This is
    /// a belt-and-suspenders layer alongside <see cref="ModularCA.API.Middleware.ReservedCaLabelGuardMiddleware"/>:
    /// even if the reserved-label guard is ever removed or bypassed, the per-CA
    /// enablement check still refuses every enrollment request for the system CA.
    /// No signing / cert / request profiles are attached — these configs are not
    /// intended to be flipped on via the admin API (which also refuses the label).
    /// </summary>
    public static void SeedSystemCaProtocolConfigs(ModularCADbContext db, CertificateAuthorityEntity systemCa)
    {
        var protocols = new[] { "ACME", "EST", "SCEP", "CMP", "OCSP" };
        foreach (var protocol in protocols)
        {
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
            {
                CaId = systemCa.Id,
                Protocol = protocol,
                IsEnabled = false,
                IsPublicVisible = false,
            });
        }
        db.SaveChanges();
        Console.WriteLine($"✓ Protocol configs seeded DISABLED for system CA '{systemCa.Name}' — protocols are off by design.");
    }

    /// <summary>
    /// Seeds CaServiceUrls for a CA. The <paramref name="publicBaseUrl"/> is persisted on the row;
    /// <c>CaServiceUrlService.ResolveForCaAsync</c> auto-generates
    /// <c>{base}/crl/{label}</c>, <c>{base}/ocsp</c>, and <c>{base}/ca/{label}</c> at cert-build
    /// time. Operators edit the base URL via <c>AdminCaServiceUrlController</c> later. URLs are
    /// expected to be HTTP (not HTTPS) so clients can fetch CRLs and OCSP responses without the
    /// chicken-and-egg TLS validation problem.
    /// </summary>
    public static void SeedCaServiceUrls(ModularCADbContext db, CertificateEntity caCertEntity, string publicBaseUrl, string caLabel)
    {
        if (db.CaServiceUrls.Any(s => s.CaCertificateId == caCertEntity.CertificateId))
            return;

        var baseUrl = publicBaseUrl.TrimEnd('/');

        db.CaServiceUrls.Add(new CaServiceUrlEntity
        {
            CaCertificateId = caCertEntity.CertificateId,
            PublicBaseUrl = baseUrl,
        });
        db.SaveChanges();
        Console.WriteLine($"✓ Service URLs seeded for CA '{caCertEntity.SubjectDN}' (base={baseUrl}, CDP/OCSP/AIA auto-generated at build time)");
    }

    /// <summary>
    /// Adds a list of feature flag entities to the database, skipping any that already exist.
    /// </summary>
    public static void AddFeatureFlagsToDb(ModularCADbContext db, List<FeatureFlagEntity> featureFlagEntry)
    {
        foreach (var flag in featureFlagEntry)
        {
            if (!db.FeatureFlags.Any(f => f.Name == flag.Name))
                db.FeatureFlags.Add(flag);
            db.SaveChanges();
            Console.WriteLine($"✓ Feature flag '{flag.Name}' added to database.");
        }
    }

    /// <summary>
    /// Seeds the five default IP whitelist rules (System, Setup, Api, Admin, Auth)
    /// on first bootstrap. System / Setup / Api / Admin use
    /// <see cref="WhitelistDefaults.InternalOnlyCidrs"/> (RFC1918 + loopback + IPv6
    /// unique/link-local), matching the pre-bootstrap hardcoded fallback byte-for-byte.
    /// Auth defaults to <see cref="WhitelistDefaults.AllAddressesCidrs"/> so remote
    /// admin login works out of the box — the Admin rule still gates the admin API
    /// and SPA, so a public deployment can't reach /admin or /api/v1/admin even if
    /// Auth is fully open.
    /// <para>
    /// All rows are flagged <c>IsSystemDefault = true</c>; the admin API refuses to
    /// delete them but allows their CIDRs and enabled flag to be edited. Idempotent
    /// via <c>db.Whitelists.Any()</c>.
    /// </para>
    /// </summary>
    public static void SeedWhitelists(ModularCADbContext db)
    {
        if (db.Whitelists.Any())
        {
            Console.WriteLine("(i) Whitelists already seeded — skipping.");
            return;
        }

        var now = DateTime.UtcNow;
        var rows = new[]
        {
            new WhitelistEntity
            {
                Name = "System Default",
                Description = "Catch-all for any path without a more-specific scope. Covers SPA assets, favicons, root path, and anything uncategorized. Restricts to internal networks by default.",
                Scope = WhitelistScope.System,
                CertificateAuthorityId = null,
                Protocol = null,
                CidrList = WhitelistDefaults.InternalOnlyCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "Setup Wizard",
                Description = "Locks the initial setup wizard to internal networks. Matches the pre-bootstrap hardcoded fallback.",
                Scope = WhitelistScope.Setup,
                CertificateAuthorityId = null,
                Protocol = null,
                CidrList = WhitelistDefaults.InternalOnlyCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "Direct API Protocol Routes",
                Description = "Blocks /api/v1/{acme,scep,est,cmp,public/ocsp,public/tsa,public/crl,public/ca} from external clients, forcing canonical short-URL use.",
                Scope = WhitelistScope.Api,
                CertificateAuthorityId = null,
                Protocol = null,
                CidrList = WhitelistDefaults.InternalOnlyCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "Admin Surface",
                Description = "Locks the admin SPA (/admin/*) and admin API (/api/v1/admin/*) to internal networks so a public deployment cannot serve the admin console or receive admin API calls from the internet. Pairs with JWT + MFA as layered defense.",
                Scope = WhitelistScope.Admin,
                CertificateAuthorityId = null,
                Protocol = null,
                CidrList = WhitelistDefaults.InternalOnlyCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "Auth Endpoints",
                Description = "Controls access to /auth/* and /api/v1/auth/* (login, refresh, MFA). Open to all by default so remote admin login works out of the box — access to admin endpoints themselves is still gated by the Admin scope rule.",
                Scope = WhitelistScope.Auth,
                CertificateAuthorityId = null,
                Protocol = null,
                CidrList = WhitelistDefaults.AllAddressesCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            // ── Global per-protocol baseline ────────────────────────────
            // These three cover the PKI-universal "must be public" endpoints
            // — relying parties can't validate certs without OCSP/CRL, and
            // clients can't build chains without the CA cert download. Seeded
            // at Protocol scope with CaId=null so they apply across every CA
            // without operators having to enumerate rules per-CA. Enrollment
            // protocols (ACME/EST/SCEP/CMP) and TSA remain unseeded — those
            // are deployment-specific and operators open them explicitly.
            new WhitelistEntity
            {
                Name = "OCSP (global)",
                Description = "OCSP responder must be publicly reachable so relying parties (browsers, OS trust stores) can validate certificates. Applies to every CA's OCSP endpoint via both the /ocsp short URL and /api/v1/public/ocsp.",
                Scope = WhitelistScope.Protocol,
                CertificateAuthorityId = null,
                Protocol = "OCSP",
                CidrList = WhitelistDefaults.AllAddressesCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "CRL (global)",
                Description = "CRL distribution points referenced in issued certs (CDP extension) must be publicly reachable. Applies to every CA's CRL download endpoint via both /crl/{label} and /api/v1/public/crl.",
                Scope = WhitelistScope.Protocol,
                CertificateAuthorityId = null,
                Protocol = "CRL",
                CidrList = WhitelistDefaults.AllAddressesCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new WhitelistEntity
            {
                Name = "CA cert download (global)",
                Description = "AIA-pointed CA certificate download endpoints must be publicly reachable so clients can build chains. Applies to every CA's /ca/{label} endpoint (and /api/v1/public/ca/{label}).",
                Scope = WhitelistScope.Protocol,
                CertificateAuthorityId = null,
                Protocol = "CA",
                CidrList = WhitelistDefaults.AllAddressesCidrs.ToList(),
                IsEnabled = true,
                IsSystemDefault = true,
                CreatedAt = now,
                UpdatedAt = now,
            },
        };

        db.Whitelists.AddRange(rows);
        db.SaveChanges();
        Console.WriteLine("✓ Whitelists seeded (System, Setup, Api, Admin, Auth + OCSP/CRL/CA global — 8 default rules).");
    }

    /// <summary>
    /// Seeds the default password policy into the database if none exists.
    /// </summary>
    public static void SeedPasswordPolicy(ModularCADbContext db)
    {
        if (db.PasswordPolicies.Any()) return;
        db.PasswordPolicies.Add(new PasswordPolicyEntity());
        db.SaveChanges();
        Console.WriteLine("✓ Default password policy created.");
    }

    /// <summary>
    /// Seeds the default runtime security policy (session/lockout, MFA, OCSP) if none exists.
    /// Setup-wizard values (<paramref name="maxFailedLoginAttempts"/>, <paramref name="lockoutMinutes"/>)
    /// override the entity defaults when provided, so operator choices from the wizard land in DB
    /// rather than config.yaml (where they used to silently vanish after the yaml migration).
    /// </summary>
    public static void SeedSecurityPolicy(
        ModularCADbContext db,
        int? maxFailedLoginAttempts = null,
        int? lockoutMinutes = null)
    {
        if (db.SecurityPolicies.Any()) return;
        var entity = new SecurityPolicyEntity();
        if (maxFailedLoginAttempts is int mfa && mfa >= 1) entity.MaxFailedLoginAttempts = mfa;
        if (lockoutMinutes is int lm && lm >= 0) entity.LockoutMinutes = lm;
        db.SecurityPolicies.Add(entity);
        db.SaveChanges();
        Console.WriteLine($"✓ Default security policy created (MaxFailedLoginAttempts={entity.MaxFailedLoginAttempts}, LockoutMinutes={entity.LockoutMinutes}).");
    }

    /// <summary>
    /// Seeds the default LDAP publisher policy (master gate + tunables) if none exists.
    /// </summary>
    public static void SeedLdapPublisherPolicy(ModularCADbContext db)
    {
        if (db.LdapPublisherPolicies.Any()) return;
        db.LdapPublisherPolicies.Add(new LdapPublisherPolicyEntity());
        db.SaveChanges();
        Console.WriteLine("✓ Default LDAP publisher policy created.");
    }

    /// <summary>
    /// Seeds default per-protocol rate-limit rows if none exist. Covers every
    /// enrollment / revocation / timestamping protocol with sensible per-IP per-minute
    /// defaults. The middleware falls back to its own built-in defaults for protocols
    /// not listed here (CRL/CA/HEALTH/short-URL variants) and for rows an operator
    /// may later DELETE via the admin API.
    /// </summary>
    public static void SeedProtocolRateLimits(ModularCADbContext db)
    {
        if (db.ProtocolRateLimits.Any()) return;
        db.ProtocolRateLimits.AddRange(
            // Enrollment protocols — moderate throughput.
            new ProtocolRateLimitEntity { Protocol = "EST", MaxRequests = 100, WindowMinutes = 1 },
            new ProtocolRateLimitEntity { Protocol = "SCEP", MaxRequests = 50, WindowMinutes = 1 },
            new ProtocolRateLimitEntity { Protocol = "CMP", MaxRequests = 100, WindowMinutes = 1 },
            new ProtocolRateLimitEntity { Protocol = "ACME", MaxRequests = 200, WindowMinutes = 1 },
            // OCSP is queried continuously by relying parties — looser cap.
            new ProtocolRateLimitEntity { Protocol = "OCSP", MaxRequests = 1000, WindowMinutes = 1 },
            // RFC 3161 timestamping.
            new ProtocolRateLimitEntity { Protocol = "TSA", MaxRequests = 500, WindowMinutes = 1 });
        db.SaveChanges();
        Console.WriteLine("✓ Default protocol rate limits created (EST/SCEP/CMP/ACME/OCSP/TSA).");
    }

    /// <summary>
    /// Seeds default notification preference records for certificate lifecycle
    /// and security events.
    /// </summary>
    public static void SeedNotificationPreferences(ModularCADbContext db)
    {
        if (db.NotificationPreferences.Any()) return;

        var prefs = new[]
        {
            new NotificationPreferenceEntity { EventType = "CertExpiring", Enabled = true, DaysBeforeExpiry = 30, Description = "Certificate approaching expiry" },
            new NotificationPreferenceEntity { EventType = "CertRevoked", Enabled = true, Description = "Certificate revoked" },
            new NotificationPreferenceEntity { EventType = "CertIssued", Enabled = false, Description = "New certificate issued" },
            new NotificationPreferenceEntity { EventType = "AccountLocked", Enabled = true, Description = "User account locked out" },
            new NotificationPreferenceEntity { EventType = "PasswordReset", Enabled = true, Description = "User password reset by admin" },
            new NotificationPreferenceEntity { EventType = "PasswordExpiring", Enabled = true, DaysBeforeExpiry = 14, Description = "User password approaching expiry" },
            new NotificationPreferenceEntity { EventType = "CrlGenerationFailed", Enabled = true, Description = "CRL generation failure" },
            new NotificationPreferenceEntity { EventType = "TlsCertRenewed", Enabled = true, Description = "API TLS certificate auto-renewed" },
        };

        db.NotificationPreferences.AddRange(prefs);
        db.SaveChanges();
        Console.WriteLine($"✓ {prefs.Length} notification preferences seeded.");
    }

    /// <summary>
    /// Seeds system-wide certificate profiles for infrastructure certs (TSA signer, OCSP responder).
    /// These profiles enforce EKU, key algorithm, and validity constraints on auto-generated infra certs.
    /// Idempotent — skips profiles that already exist.
    /// </summary>
    public static void SeedInfrastructureCertProfiles(ModularCADbContext db)
    {
        var keyAlgorithms = JsonSerializer.Serialize(new[] { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" });
        var keySizes = JsonSerializer.Serialize(new[] { "2048", "3072", "4096", "7680", "8192", "P-256", "P-384", "P-521" });
        var sigAlgorithms = JsonSerializer.Serialize(new[] { "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" });

        // TSA Certificate Profile
        if (!db.CertProfiles.Any(c => c.Name == "TSA Certificate Profile"))
        {
            var tsaKeyUsages = SetupAllowedStandardOidsJson(new[] { "Digital Signature" }, db);
            var tsaEkus = SetupAllowedExtendedOidsJson(new[] { "Time Stamping" }, db);
            var tsaProfile = new CertProfileEntity
            {
                Name = "TSA Certificate Profile",
                Description = "Profile for TSA signer certificates (RFC 3161). EKU marked critical.",
                IsCaProfile = false,
                KeyUsages = tsaKeyUsages,
                ExtendedKeyUsages = tsaEkus,
                AllowedKeyAlgorithms = keyAlgorithms,
                AllowedKeySizes = keySizes,
                AllowedSignatureAlgorithms = sigAlgorithms,
                ValidityPeriodMin = "P1D",
                ValidityPeriodMax = "P10Y",
                CanBeDeleted = false,
                CreatedAt = DateTime.UtcNow,
            };
            db.CertProfiles.Add(tsaProfile);
            db.SaveChanges();
            Console.WriteLine($"✓ Certificate profile '{tsaProfile.Name}' seeded.");
        }

        // OCSP Responder Certificate Profile
        if (!db.CertProfiles.Any(c => c.Name == "OCSP Responder Certificate Profile"))
        {
            var ocspKeyUsages = SetupAllowedStandardOidsJson(new[] { "Digital Signature" }, db);
            var ocspEkus = SetupAllowedExtendedOidsJson(new[] { "OCSP Signer" }, db);
            var ocspProfile = new CertProfileEntity
            {
                Name = "OCSP Responder Certificate Profile",
                Description = "Profile for delegated OCSP responder certificates (RFC 6960). Auto-adds id-pkix-ocsp-nocheck.",
                IsCaProfile = false,
                KeyUsages = ocspKeyUsages,
                ExtendedKeyUsages = ocspEkus,
                AllowedKeyAlgorithms = keyAlgorithms,
                AllowedKeySizes = keySizes,
                AllowedSignatureAlgorithms = sigAlgorithms,
                ValidityPeriodMin = "P1D",
                ValidityPeriodMax = "P10Y",
                CanBeDeleted = false,
                CreatedAt = DateTime.UtcNow,
            };
            db.CertProfiles.Add(ocspProfile);
            db.SaveChanges();
            Console.WriteLine($"✓ Certificate profile '{ocspProfile.Name}' seeded.");
        }

        // Web TLS Certificate Profile
        if (!db.CertProfiles.Any(c => c.Name == "Web TLS Certificate Profile"))
        {
            var tlsKeyUsages = SetupAllowedStandardOidsJson(new[] { "Digital Signature", "Key Encipherment" }, db);
            var tlsEkus = SetupAllowedExtendedOidsJson(new[] { "Server Authentication" }, db);
            var tlsProfile = new CertProfileEntity
            {
                Name = "Web TLS Certificate Profile",
                Description = "Profile for the management UI/API TLS certificate. CA/B Forum BR max 397 days.",
                IsCaProfile = false,
                KeyUsages = tlsKeyUsages,
                ExtendedKeyUsages = tlsEkus,
                AllowedKeyAlgorithms = keyAlgorithms,
                AllowedKeySizes = keySizes,
                AllowedSignatureAlgorithms = sigAlgorithms,
                ValidityPeriodMin = "P30D",
                ValidityPeriodMax = "P397D",
                CanBeDeleted = false,
                CreatedAt = DateTime.UtcNow,
            };
            db.CertProfiles.Add(tlsProfile);
            db.SaveChanges();
            Console.WriteLine($"✓ Certificate profile '{tlsProfile.Name}' seeded.");
        }
    }

    /// <summary>
    /// Seeds the four built-in roles (Administrator, Operator, Auditor, Requester) if they don't exist.
    /// Must be called before any group or user role assignments are created.
    /// </summary>
    public static void SeedBuiltInRoles(ModularCADbContext db)
    {
        var templates = new[]
        {
            ("Administrator", "Full system and CA management access", Capabilities.AdministratorTemplate),
            ("Operator", "Operational certificate and token management", Capabilities.OperatorTemplate),
            ("Auditor", "Read-only access to certificates, profiles, and audit logs", Capabilities.AuditorTemplate),
            ("Requester", "Certificate request and view access", Capabilities.RequesterTemplate),
        };

        var created = 0;
        foreach (var (name, description, caps) in templates)
        {
            if (db.Roles.Any(r => r.Name == name && r.IsBuiltIn))
                continue;

            var role = new RoleEntity
            {
                Name = name,
                Description = description,
                IsBuiltIn = true,
                TenantId = null, // system-wide
            };
            db.Roles.Add(role);
            db.SaveChanges();

            foreach (var cap in caps)
            {
                db.RoleCapabilities.Add(new RoleCapabilityEntity { RoleId = role.Id, Capability = cap });
            }
            db.SaveChanges();
            created++;
        }
        if (created > 0)
            Console.WriteLine($"✓ {created} built-in role(s) seeded.");
    }

    /// <summary>
    /// Assigns a built-in role to a group. Creates both a RoleAssignment and direct
    /// CapabilityGrant rows (for backward compatibility with existing queries).
    /// Delegates to <see cref="RoleAssignmentHelper.AssignBuiltInRoleToGroup"/> in
    /// ModularCA.Database so the same logic is available to Core services without a
    /// circular project reference.
    /// </summary>
    public static void AssignBuiltInRoleToGroup(ModularCADbContext db, CaGroupEntity group, string templateName)
        => RoleAssignmentHelper.AssignBuiltInRoleToGroup(db, group, templateName);

    /// <summary>
    /// Creates the four system-wide authorization groups (system-super, system-admin, system-operator, system-auditor).
    /// Must be called after tenants are created and before any users are created.
    /// All system groups belong to the System tenant.
    /// </summary>
    /// <param name="db">The bootstrap database context.</param>
    /// <param name="systemTenantId">The ID of the System tenant that owns these groups.</param>
    public static void CreateSystemGroups(ModularCADbContext db, Guid systemTenantId)
    {
        // Tuple: (name, displayName, templateName, isTierSuper). Only system-super carries
        // the super-tier flag; every other system group is a regular system tier (admin /
        // operator / auditor) distinguished by IsSystemGroup && !IsSystemTierSuper.
        var systemGroups = new[]
        {
            ("system-super", "System Super Admin", "Administrator", true),
            ("system-admin", "System Admin", "Administrator", false),
            ("system-operator", "System Operator", "Operator", false),
            ("system-auditor", "System Auditor", "Auditor", false),
        };

        var created = 0;
        foreach (var (name, displayName, templateName, isTierSuper) in systemGroups)
        {
            if (db.CaGroups.Any(g => g.Name == name))
                continue;

            var group = new CaGroupEntity
            {
                Name = name,
                DisplayName = displayName,
                TemplateName = templateName,
                IsSystemGroup = true,
                IsSystemTierSuper = isTierSuper,
                IsAutoGenerated = true,
                TenantId = systemTenantId,
            };
            db.CaGroups.Add(group);
            db.SaveChanges();

            AssignBuiltInRoleToGroup(db, group, templateName);
            created++;
        }
        Console.WriteLine($"✓ System groups created ({created} new, {systemGroups.Length - created} existing).");
    }

    /// <summary>
    /// Creates the four CA-scoped authorization groups (admin, operator, auditor, user) for the given CA.
    /// Must be called after the CA entity and its tenant are created in the database.
    /// Groups inherit the CA's tenant ID.
    /// </summary>
    /// <param name="db">The bootstrap database context.</param>
    /// <param name="caEntity">The certificate authority entity to create groups for.</param>
    /// <param name="tenantId">The tenant ID to assign to each CA-scoped group.</param>
    public static void CreateCaGroups(ModularCADbContext db, CertificateAuthorityEntity caEntity, Guid tenantId)
    {
        var caLabel = caEntity.Label ?? caEntity.Name.ToLowerInvariant().Replace(' ', '-');
        var caName = caEntity.Name;

        if (db.CaGroups.Any(g => g.CertificateAuthorityId == caEntity.Id))
        {
            Console.WriteLine($"✓ CA groups already exist for '{caName}'.");
            return;
        }

        var templateRoles = new[]
        {
            ("Administrator", "admin", "Admin"),
            ("Operator", "operator", "Operator"),
            ("Auditor", "auditor", "Auditor"),
            ("Requester", "user", "User")
        };

        // Namespace the group names with the tenant slug so two tenants with
        // the same CA label can't collide on the CaGroups.Name unique index. Without this,
        // two "default" CAs in separate tenants would both want to create "default-admin".
        var tenant = db.Tenants.FirstOrDefault(t => t.Id == tenantId)
            ?? throw new InvalidOperationException($"Tenant '{tenantId}' not found — cannot create CA groups.");
        var tenantSlug = tenant.Slug;

        var created = new List<string>();
        foreach (var (templateName, suffix, displaySuffix) in templateRoles)
        {
            // Group-name format is `{tenantSlug}_{caLabel}_{role}`.
            // Underscore separators between the three segments make the boundaries
            // unambiguous even when tenantSlug or caLabel contains hyphens of their own
            // (e.g. `modularca_modularca-root-cert-1_admin` is clearly tenant=modularca,
            // CA=modularca-root-cert-1, role=admin).
            var groupName = $"{tenantSlug}_{caLabel}_{suffix}";
            // Fail LOUDLY on collision. A leftover group from a previous failed
            // bootstrap (or a manual insert) must not silently grant access to the new CA.
            // The caller is expected to run --reset or resolve the conflict manually.
            var existing = db.CaGroups.FirstOrDefault(g => g.Name == groupName);
            if (existing != null)
            {
                if (existing.CertificateAuthorityId != caEntity.Id)
                {
                    throw new InvalidOperationException(
                        $"Group '{groupName}' already exists but is bound to a different CA " +
                        $"(existing CAId={existing.CertificateAuthorityId}, new CAId={caEntity.Id}). " +
                        "Refusing to bootstrap with a partial auth-group set — run --reset or delete the stale group.");
                }
                // Same CA — this is a re-run idempotency case, continue.
                continue;
            }

            var group = new CaGroupEntity
            {
                Name = groupName,
                DisplayName = $"{caName} {displaySuffix}",
                CertificateAuthorityId = caEntity.Id,
                TemplateName = templateName,
                IsSystemGroup = false,
                IsAutoGenerated = true,
                TenantId = tenantId,
            };
            db.CaGroups.Add(group);
            db.SaveChanges();

            AssignBuiltInRoleToGroup(db, group, templateName);
            created.Add(groupName);
        }
        if (created.Count > 0)
        {
            db.SaveChanges();
            Console.WriteLine($"✓ CA groups created for '{caName}' ({string.Join(", ", created)}).");
        }
        else
        {
            Console.WriteLine($"✓ CA groups for '{caName}' already covered by existing groups.");
        }
    }

    /// <summary>
    /// Seeds default SSH CA profiles (signing, cert, and request profiles) if none exist.
    /// Creates one user signing profile, one host signing profile, one cert profile for each type,
    /// and a default request profile.
    /// </summary>
    public static void SeedDefaultSshProfiles(ModularCADbContext db)
    {
        if (db.SshCertProfiles.Any())
        {
            Console.WriteLine("✓ SSH CA profiles already seeded.");
            return;
        }

        // SSH Cert Profiles (signing profiles are auto-created when SSH CA keys are generated)
        var userCertProfile = new SshCertProfileEntity
        {
            Name = "SSH User Cert - Standard",
            Description = "Standard user certificate profile. Allows common principals, standard extensions.",
            AllowedPrincipalPatterns = "[\"^[a-z_][a-z0-9_-]{0,31}$\"]", // POSIX username pattern
            MaxPrincipals = 5,
            AllowedExtensions = "[\"permit-pty\",\"permit-agent-forwarding\",\"permit-port-forwarding\",\"permit-X11-forwarding\",\"permit-user-rc\"]",
            RequiredExtensions = "[]",
            MaxValidityHours = 24,
        };
        db.SshCertProfiles.Add(userCertProfile);

        var hostCertProfile = new SshCertProfileEntity
        {
            Name = "SSH Host Cert - Standard",
            Description = "Standard host certificate profile. Allows FQDN principals.",
            AllowedPrincipalPatterns = "[\"^[a-z0-9][a-z0-9.-]+$\"]", // hostname/FQDN pattern
            MaxPrincipals = 10,
            AllowedExtensions = "[]",
            RequiredExtensions = "[]",
            MaxValidityHours = 8760,
        };
        db.SshCertProfiles.Add(hostCertProfile);

        // SSH Request Profiles
        var userRequestProfile = new SshRequestProfileEntity
        {
            Name = "SSH User Request - Default",
            Description = "Default request profile for SSH user certificates. No approval required.",
            RequireApproval = false,
            MaxValidityHours = 24,
        };
        db.SshRequestProfiles.Add(userRequestProfile);

        var hostRequestProfile = new SshRequestProfileEntity
        {
            Name = "SSH Host Request - Default",
            Description = "Default request profile for SSH host certificates. No approval required.",
            RequireApproval = false,
            MaxValidityHours = 8760, // 1 year
        };
        db.SshRequestProfiles.Add(hostRequestProfile);
        db.SaveChanges();

        // Set allowed cert profile IDs (signing profiles are created when SSH CA keys are generated)
        userRequestProfile.AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { userCertProfile.Id });
        hostRequestProfile.AllowedSshCertProfileIds = JsonSerializer.Serialize(new[] { hostCertProfile.Id });
        db.SaveChanges();

        Console.WriteLine("✓ Default SSH CA profiles seeded (2 cert, 2 request). Signing profiles are created with SSH CA keys.");
    }

    /// <summary>
    /// Creates the initial superadmin user with a generated password that meets the seeded policy.
    /// Assigns the user to the system-admin group and all CA-level admin groups.
    /// Prints the generated password to the console.
    /// </summary>
    public static void CreateInitialUser(ModularCADbContext db)
    {
        var policy = db.PasswordPolicies.FirstOrDefault() ?? new PasswordPolicyEntity();
        var minLen = Math.Max(policy.MinLength, 16);
        string password;
        int attempts = 0;
        do
        {
            password = ModularCA.Auth.Utils.PasswordUtil.Generate(minLen);
            attempts++;
            if (attempts > 100)
                throw new InvalidOperationException("Failed to generate a password meeting policy after 100 attempts. Check dictionary settings.");
        }
        while (!MeetsPolicy(password, policy));

        var initialUser = new UserEntity
        {
            Username = "superadmin",
            PasswordHash = ModularCA.Auth.Utils.PasswordUtil.HashPassword(password),
            CreatedAt = DateTime.UtcNow,
            // The generated password is delivered by printing it to the operator's terminal —
            // the only channel available during a headless bootstrap, but one that leaves the
            // secret in scrollback, screen recordings and anything that captures stdout.
            // Requiring a change on first login bounds how long that copy is worth anything.
            // AuthController answers 403 { requirePasswordChange } and the pre-JWT
            // /auth/change-password endpoint clears the flag.
            PasswordChangeOnNextLogon = true,
        };
        db.Users.Add(initialUser);
        db.SaveChanges();

        // Assign to system-super group (allows self-approval of CSRs)
        var systemSuperGroup = db.CaGroups.First(g => g.Name == "system-super");
        db.CaGroupMembers.Add(new CaGroupMemberEntity
        {
            GroupId = systemSuperGroup.Id,
            UserId = initialUser.Id,
            AddedAt = DateTime.UtcNow,
        });

        // Assign to system-admin group
        var systemAdminGroup = db.CaGroups.First(g => g.Name == "system-admin");
        db.CaGroupMembers.Add(new CaGroupMemberEntity
        {
            GroupId = systemAdminGroup.Id,
            UserId = initialUser.Id,
            AddedAt = DateTime.UtcNow,
        });
        db.SaveChanges();

        // Assign to all CA-level admin groups
        var caAdminGroups = db.CaGroups
            .Where(g => g.Grants.Any(gr => gr.Capability == Capabilities.CaManage) && !g.IsSystemGroup)
            .ToList();
        foreach (var group in caAdminGroups)
        {
            db.CaGroupMembers.Add(new CaGroupMemberEntity
            {
                GroupId = group.Id,
                UserId = initialUser.Id,
                AddedAt = DateTime.UtcNow,
            });
        }
        db.SaveChanges();

        Console.WriteLine($"✓ Initial user '{initialUser.Username}' created.");
        Console.WriteLine($"  Assigned to: system-admin + {caAdminGroups.Count} CA admin group(s).");

        // The generated admin password must be recorded by the operator
        // exactly once. Print it with a loud banner on an interactive TTY, and on POSIX also
        // write it to /dev/tty if available so it survives when the caller pipes stdout
        // through tee/script(1)/CI capture. The /dev/tty branch is best-effort — we never
        // fail the bootstrap if it is not writable.
        Console.WriteLine();
        Console.WriteLine("================================================================");
        Console.WriteLine("!!! RECORD THIS PASSWORD NOW — IT CANNOT BE RECOVERED LATER !!!");
        Console.WriteLine($"    Initial admin password: {password}");
        Console.WriteLine("================================================================");
        Console.WriteLine();

        if (!OperatingSystem.IsWindows())
        {
            try
            {
                if (File.Exists("/dev/tty"))
                {
                    using var tty = new FileStream("/dev/tty", FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    using var writer = new StreamWriter(tty);
                    writer.WriteLine();
                    writer.WriteLine("================================================================");
                    writer.WriteLine("!!! RECORD THIS PASSWORD NOW — IT CANNOT BE RECOVERED LATER !!!");
                    writer.WriteLine($"    Initial admin password: {password}");
                    writer.WriteLine("================================================================");
                    writer.WriteLine();
                }
            }
            catch
            {
                // best-effort: /dev/tty not available (non-interactive, chroot, etc.)
            }
        }
    }

    /// <summary>
    /// Checks whether a password meets all constraints defined by the given password policy.
    /// <para>
    /// Delegates to <see cref="ModularCA.Auth.Services.PasswordPolicyService.Validate"/> rather
    /// than reimplementing the rules. This method used to carry its own copy of length,
    /// complexity and dictionary checking, and the duplication is how the gap arose: the
    /// runtime enforced the full policy on every password change, while the bootstrap
    /// wizard's admin password was validated by neither copy.
    /// </para>
    /// </summary>
    internal static bool MeetsPolicy(string password, PasswordPolicyEntity policy)
        => ModularCA.Auth.Services.PasswordPolicyService.Validate(password, policy).Count == 0;
}
