using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Setup;
using ModularCA.Shared.Utils;
using MySqlConnector;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.Data;
using System.Text.Json;
using static ModularCA.Keystore.Services.KeystoreService;

namespace ModularCA.Bootstrap;

/// <summary>
/// Service wrapper around the bootstrap procedure that can be called from both
/// the CLI (BootstrapModularCA.Run) and the web setup wizard (SetupController).
/// Accepts a <see cref="SetupRequest"/> and performs all CA initialization steps
/// without any console I/O.
/// </summary>
public class BootstrapService
{
    /// <summary>
    /// Executes the full bootstrap procedure using values from a web setup request.
    /// Returns a <see cref="SetupResponse"/> with success/error info and the generated admin password.
    /// When <paramref name="serviceProvider"/> is supplied, the method resolves
    /// <see cref="IWhitelistService"/> after seeding and calls <c>ReloadAsync</c> so the live
    /// singleton snapshot picks up the freshly-seeded rows before the wizard returns.
    /// </summary>
    public static SetupResponse RunFromSetupRequest(SetupRequest request, IServiceProvider? serviceProvider = null)
    {
        var warnings = new List<string>();

        try
        {
            // === Build a BootstrapConfig-equivalent from the SetupRequest ===
            var configDir = Path.Combine(AppContext.BaseDirectory, "config");
            var keystoreDir = Path.Combine(AppContext.BaseDirectory, "keystores");
            string certPath = Path.Combine(keystoreDir, "ca-certs.keystore");
            string trustPath = Path.Combine(keystoreDir, "ca-trust.keystore");
            var OIDPath = Path.Combine(configDir, "OIDSeed.yaml");
            var OIDConfig = YamlOIDLoader.Load(OIDPath);

            // Map SetupRequest to the structures BootstrapModularCA helpers expect
            var bootstrapConfig = MapToBootstrapConfig(request);

            // setup-database.yaml is the authoritative source for DB connection parameters
            // once SaveDatabaseCredentials has run. The Initialize payload may carry stale
            // defaults if the browser refreshed between save and initialize (React state
            // reseeds from initialData), so prefer the on-disk file and fall back to the
            // request only when the file is absent.
            var setupDbYamlPath = Path.Combine(configDir, "setup-database.yaml");
            var persistedSetupDb = YamlSetupDatabaseLoader.Load(setupDbYamlPath);

            // Honor the operator-selected TLS mode from whichever
            // source is authoritative. Unparseable values clamp back to Required so a typo
            // can't silently disable TLS.
            var effectiveSslModeRaw = !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlApp?.SslMode)
                ? persistedSetupDb.SqlApp.SslMode
                : (!string.IsNullOrWhiteSpace(persistedSetupDb?.SqlRoot?.SslMode)
                    ? persistedSetupDb.SqlRoot.SslMode
                    : request.Database.SslMode);
            var selectedSslMode = Enum.TryParse<MySqlSslMode>(
                effectiveSslModeRaw, ignoreCase: true, out var _selSsl)
                ? _selSsl : MySqlSslMode.Required;
            var selectedSslModeString = selectedSslMode.ToString();

            // Prefer values from setup-database.yaml for every DB field. Fall back to the
            // request payload for any field the file lacks (covers the edge case where
            // the file exists but is partially populated).
            string RootHost() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlRoot?.Host) ? persistedSetupDb.SqlRoot.Host : request.Database.RootHost;
            int RootPort() => (persistedSetupDb?.SqlRoot?.Port ?? 0) > 0 ? persistedSetupDb!.SqlRoot.Port : request.Database.RootPort;
            string RootUser() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlRoot?.Username) ? persistedSetupDb.SqlRoot.Username : request.Database.RootUsername;
            string RootPass() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlRoot?.Password) ? persistedSetupDb.SqlRoot.Password : request.Database.RootPassword;
            string AppDb() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlApp?.Database) ? persistedSetupDb.SqlApp.Database : request.Database.AppDatabase;
            string AppUser() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlApp?.Username) ? persistedSetupDb.SqlApp.Username : request.Database.AppUsername;
            string AuditDb() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlAudit?.Database) ? persistedSetupDb.SqlAudit.Database : request.Database.AuditDatabase;
            string AuditUser() => !string.IsNullOrWhiteSpace(persistedSetupDb?.SqlAudit?.Username) ? persistedSetupDb.SqlAudit.Username : request.Database.AuditUsername;

            var setupDbConfig = new YamlSetupDatabaseLoader.SetupDatabaseConfig
            {
                SqlRoot = new YamlSetupDatabaseLoader.SqlConnectionConfig
                {
                    Host = RootHost(),
                    Port = RootPort(),
                    Username = RootUser(),
                    Password = RootPass(),
                    Database = AppDb(),
                    SslMode = selectedSslModeString
                },
                SqlApp = new YamlSetupDatabaseLoader.SqlConnectionConfig
                {
                    Host = RootHost(),
                    Port = RootPort(),
                    Username = AppUser(),
                    Database = AppDb(),
                    SslMode = selectedSslModeString
                },
                SqlAudit = new YamlSetupDatabaseLoader.SqlConnectionConfig
                {
                    Host = RootHost(),
                    Port = RootPort(),
                    Username = AuditUser(),
                    Database = AuditDb(),
                    SslMode = selectedSslModeString
                }
            };

            var rootConfig = !string.IsNullOrWhiteSpace(setupDbConfig.SqlRoot.Password)
                ? setupDbConfig.SqlRoot
                : setupDbConfig.SqlApp;

            // Apply the operator-selected TLS mode for the setup-wizard
            // root-credential pass. Defaults to Required when no choice was provided.
            var rootConnBuilder = new MySqlConnectionStringBuilder
            {
                Server = rootConfig.Host,
                Port = (uint)rootConfig.Port,
                Database = setupDbConfig.SqlApp.Database,
                UserID = rootConfig.Username,
                Password = rootConfig.Password,
                SslMode = selectedSslMode
            };
            var rootConnStr = rootConnBuilder.ConnectionString;

            // === Clean state — ensure fresh database schema ===
            BootstrapModularCA.DeleteArtifacts(certPath, trustPath);

            // Drop and recreate DB to ensure clean schema (handles partial previous setups).
            // Unlike the migration-failure paths, this drop is deliberate: the setup wizard only
            // runs when IsConfigured() is false, i.e. there is no install to protect. It is NOT
            // error recovery and must not become it.
            {
                using var tempCtx = BootstrapModularCA.CreateDbContext(rootConnStr);
                tempCtx.Database.EnsureDeleted();
                Console.WriteLine("✓ Database cleaned for fresh setup");
            }

            // Create database with clean migrations
            var (dbContext, dbConnection) = BootstrapModularCA.CreateDatabaseConnection(rootConnStr);

            // === Tenants ===
            var systemTenant = dbContext.Tenants.FirstOrDefault(t => t.IsSystemTenant);
            if (systemTenant == null)
            {
                systemTenant = new TenantEntity
                {
                    Name = "System",
                    Slug = "system",
                    Description = "Internal system tenant for infrastructure CAs and system groups",
                    IsSystemTenant = true,
                    CanBeDeleted = false,
                    IsEnabled = true,
                };
                dbContext.Tenants.Add(systemTenant);
                dbContext.SaveChanges();
            }

            // === Tenant-level permission groups for system tenant ===
            BootstrapModularCA.CreateTenantGroups(dbContext, systemTenant);

            var orgName = request.Organization.Name;
            if (string.IsNullOrWhiteSpace(orgName)) orgName = request.RootCa.Organization;
            if (string.IsNullOrWhiteSpace(orgName)) orgName = "Default";
            var orgSlug = orgName.ToLowerInvariant().Replace(" ", "-").Replace(".", "-");
            var orgTenant = dbContext.Tenants.FirstOrDefault(t => t.Slug == orgSlug);
            if (orgTenant == null)
            {
                orgTenant = new TenantEntity
                {
                    Name = orgName,
                    Slug = orgSlug,
                    Description = !string.IsNullOrWhiteSpace(request.Organization.Description)
                        ? request.Organization.Description
                        : $"Primary tenant for {orgName} certificate authorities",
                    CanBeDeleted = false,
                    IsEnabled = true,
                };
                dbContext.Tenants.Add(orgTenant);
                dbContext.SaveChanges();
            }

            // === Tenant-level permission groups for org tenant ===
            BootstrapModularCA.CreateTenantGroups(dbContext, orgTenant);

            // === Built-in Roles & System Groups ===
            BootstrapProfileSeeder.SeedBuiltInRoles(dbContext);
            BootstrapProfileSeeder.CreateSystemGroups(dbContext, systemTenant.Id);

            // === OID Loading ===
            BootstrapProfileSeeder.LoadOidsToDb(dbContext, OIDConfig);

            // What the CA may put in the certificates it ISSUES. Kept at all six so that
            // "reissue infrastructure certificates" can rotate this CA's own OCSP responder and
            // TSA — see the signing-profile comment below.
            var allowedRootCaExtendedOids = new[] { "Server Authentication", "Client Authentication", "Code Signing", "Email Protection", "Time Stamping", "OCSP Signer" };

            // What the CA's own certificate asserts — a different question from the list above.
            //
            // No EKU: RFC 5280 §4.2.1.12 makes an EKU on a CA constrain every certificate beneath
            // it, so a smartcardLogon or kdcAuthentication leaf under a root carrying the
            // six-entry list fails EKU-nesting in Windows CryptoAPI with CERT_E_WRONG_USAGE.
            // CA/B BR §7.1.2.1.2 forbids extKeyUsage on a root outright.
            //
            // No keyEncipherment: RFC 5480 §3 forbids that bit for id-ecPublicKey and RFC 8410 §5
            // for Ed25519. A CA key signs; it never encrypts.
            //
            // Matches what CaCreationService emits for runtime-created CAs.
            var rootCaCertificateStandardOids = new[] { "Digital Signature", "Key Certificate Signing", "CRL Signing" };
            var rootCaCertificateExtendedOids = Array.Empty<string>();

            var RootCaStandardOidsJson = BootstrapProfileSeeder.SetupAllowedStandardOidsJson(rootCaCertificateStandardOids, dbContext);
            var RootCaExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(rootCaCertificateExtendedOids, dbContext);

            var KeyAlgorithms = new List<string> { "RSA", "ECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };
            var KeySizes = new List<string> { "2048", "3072", "4096", "7680", "8192", "P-256", "P-384", "P-521" };
            var SignatureAlgorithms = new List<string> { "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F" };

            var KeyAlgorithmsJson = JsonSerializer.Serialize(KeyAlgorithms);
            var KeySizesJson = JsonSerializer.Serialize(KeySizes);
            var SignatureAlgorithmsJson = JsonSerializer.Serialize(SignatureAlgorithms);

            // === CA Certificate Profile & Signing Profile ===
            BootstrapProfileSeeder.CreateCertProfile(dbContext, "Main CA Certificate Profile", "Default cert profile for self-signed CA certificates",
                rootCaCertificateStandardOids, rootCaCertificateExtendedOids, false, true,
                KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson, "P5Y", "P25Y");
            var caCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Main CA Certificate Profile");
            // The signing profile must permit the CA's OWN infrastructure EKUs, not just the
            // leaf ones. This used the three-entry leaf list, so the signing profile bound to
            // the bootstrap-created root permitted serverAuth/clientAuth/emailProtection only —
            // and "reissue infrastructure certificates" resolves the profile by
            // sp.IssuerId == caEntity.CertificateId, hits exactly this profile, and
            // EnsureSigningProfilePermitsInfrastructureEkus refuses for both OCSP signing and
            // time stamping. The primary CA's OCSP responder and TSA could therefore never be
            // rotated, including after a responder key compromise. It was invisible until the
            // first reissue because bootstrap issues those two certificates through
            // BootstrapCertCreator, which hardcodes the EKU and bypasses the profile.
            // CaCreationService seeds all six for runtime-created CAs; this now matches.
            // allowedCertExtendedOids remains the LEAF list, still used by the non-CA cert profile below.
            var allowedCertExtendedOids = new[] { "Server Authentication", "Client Authentication", "Email Protection" };
            var CertExtendedOidsJson = BootstrapProfileSeeder.SetupAllowedExtendedOidsJson(allowedRootCaExtendedOids, dbContext);
            var caCn = request.RootCa.CommonName ?? "ModularCA";
            var signingProfileName = $"{caCn} Signing Profile";
            BootstrapProfileSeeder.CreateSigningProfile(dbContext, signingProfileName, $"Default signing profile for {caCn}",
                null, KeyAlgorithmsJson, CertExtendedOidsJson);
            var signingProfile = BootstrapProfileSeeder.GetSigningProfileFromDb(dbContext, signingProfileName);
            BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, caCertProfile, signingProfile);

            var theOUs = !string.IsNullOrWhiteSpace(request.RootCa.OrganizationalUnit)
                ? request.RootCa.OrganizationalUnit
                : string.Empty;

            // === Self-Signed CA Certificate ===
            // SetupRootCa.KeySize is operator-supplied as a string so Ed25519/PQC can
            // ride along without a bogus "0" int default, and PQC variants (e.g. "128f"
            // vs "128s") survive the DTO round-trip. Resolve the family + variant to
            // the fully-qualified BouncyCastle algorithm name, then convert keySize to
            // the int form the cert-request pipeline expects.
            var rootCaAlgorithm = SetupKeySizeParser.ResolveAlgorithm(request.RootCa.Algorithm, request.RootCa.KeySize);
            var rootCaKeySizeInt = SetupKeySizeParser.ParseToInt(request.RootCa.Algorithm, request.RootCa.KeySize);

            var caCertRequest = BootstrapCertCreator.CreateCertificateRequest(
                request.RootCa.CommonName ?? "ModularCA",
                request.RootCa.Organization ?? string.Empty,
                theOUs,
                request.RootCa.Locality ?? string.Empty,
                request.RootCa.State ?? string.Empty,
                request.RootCa.Country ?? string.Empty,
                rootCaAlgorithm,
                rootCaKeySizeInt,
                DateTime.UtcNow,
                DateTime.UtcNow.AddYears(request.RootCa.ValidityYears),
                signingProfile.Id,
                rootCaCertificateStandardOids,
                rootCaCertificateExtendedOids,
                dbContext);

            var (signedCaCert, caPrivKey, caPrivateKeyDer) = BootstrapCertCreator.CreateSelfSignedCertificate(caCertRequest);

            // === ModularCA System Signing CA ===
            var sysCertRequest = BootstrapCertCreator.CreateCertificateRequest(
                "ModularCA System Signing CA", "ModularCA", string.Empty,
                request.RootCa.Locality ?? string.Empty, request.RootCa.State ?? string.Empty, request.RootCa.Country ?? string.Empty,
                rootCaAlgorithm, rootCaKeySizeInt,
                DateTime.UtcNow, DateTime.UtcNow.AddYears(100),
                signingProfile.Id, rootCaCertificateStandardOids, rootCaCertificateExtendedOids, dbContext);
            var (signedSysCert, sysPrivKey, sysPrivateKeyDer) = BootstrapCertCreator.CreateSelfSignedCertificate(sysCertRequest);

            var caCertPem = KeystoreService.ExportCertificateToPem(signedCaCert);
            var sysCertPem = KeystoreService.ExportCertificateToPem(signedSysCert);

            if (!Directory.Exists(keystoreDir))
                Directory.CreateDirectory(keystoreDir);

            // === Keystore Logic ===
            var keystorePasswords = new Dictionary<string, string>
            {
                { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
                { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
            };

            var keystoreFilePasswords = new Dictionary<string, string>
            {
                { "ca-certs.keystore", GenerateRandomPassphrase.Generate() },
                { "ca-trust.keystore", GenerateRandomPassphrase.Generate() }
            };

            var secondaryPasses = new Dictionary<string, string>
            {
                { "ca-certs.keystore", keystoreFilePasswords["ca-certs.keystore"] },
                { "ca-trust.keystore", keystoreFilePasswords["ca-trust.keystore"] }
            };

            // === TSA Certificate ===
            var tsaKeyGenParams = new ECKeyGenerationParameters(
                Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, new SecureRandom());
            var tsaKeyGen = new ECKeyPairGenerator();
            tsaKeyGen.Init(tsaKeyGenParams);
            var tsaKeyPair = tsaKeyGen.GenerateKeyPair();
            var tsaPrivateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(tsaKeyPair.Private).GetDerEncoded();
            var signedTsaCert = BootstrapCertCreator.SignTsaCertificate(tsaKeyPair, signedCaCert, caPrivKey);

            // OCSP responder key pair + cert
            var ocspKeyGen = new ECKeyPairGenerator();
            ocspKeyGen.Init(tsaKeyGenParams);
            var ocspKeyPair = ocspKeyGen.GenerateKeyPair();
            var ocspPrivateKeyDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ocspKeyPair.Private).GetDerEncoded();
            var signedOcspCert = BootstrapCertCreator.SignOcspResponderCertificate(ocspKeyPair, signedCaCert, caPrivKey);

            var keystoreEntries = new List<AddKeystoreEntry>
            {
                new AddKeystoreEntry("ca-trust.keystore", signedCaCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
                new AddKeystoreEntry("ca-trust.keystore", signedSysCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
                new AddKeystoreEntry("ca-trust.keystore", signedTsaCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
                new AddKeystoreEntry("ca-trust.keystore", signedOcspCert.GetEncoded(), secondaryPasses["ca-trust.keystore"]),
                new AddKeystoreEntry("ca-certs.keystore", caPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
                new AddKeystoreEntry("ca-certs.keystore", sysPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
                new AddKeystoreEntry("ca-certs.keystore", tsaPrivateKeyDer, secondaryPasses["ca-certs.keystore"]),
                new AddKeystoreEntry("ca-certs.keystore", ocspPrivateKeyDer, secondaryPasses["ca-certs.keystore"])
            };

            // === Feature Flags ===
            var defaultFlags = new List<FeatureFlagEntity>
            {
                new FeatureFlagEntity { Name = "CRL.Enabled", Enabled = request.Features.Crl, Description = "Enable CRL generation and distribution" },
                new FeatureFlagEntity { Name = "OCSP.Enabled", Enabled = request.Features.Ocsp, Description = "Enable OCSP responder" },
                new FeatureFlagEntity { Name = "ACME.Enabled", Enabled = request.Features.Acme, Description = "Enable ACME protocol endpoints" },
                new FeatureFlagEntity { Name = "EST.Enabled", Enabled = request.Features.Est, Description = "Enable EST protocol endpoints" },
                new FeatureFlagEntity { Name = "SCEP.Enabled", Enabled = request.Features.Scep, Description = "Enable SCEP protocol endpoints" },
                new FeatureFlagEntity { Name = "CMP.Enabled", Enabled = request.Features.Cmp, Description = "Enable CMP protocol endpoints" },
                new FeatureFlagEntity { Name = "MSAE.Enabled", Enabled = request.Features.Msae, Description = "Enable Windows autoenrollment (MSAE) endpoints" },
                new FeatureFlagEntity { Name = "Syslog.Enabled", Enabled = true, Description = "Enable syslog (RFC 5424) log forwarding" },
                new FeatureFlagEntity { Name = "EventLog.Enabled", Enabled = true, Description = "Enable Windows Event Log sink (Windows only)" },
                new FeatureFlagEntity { Name = "Metrics.Enabled", Enabled = true, Description = "Enable Prometheus metrics endpoint at /metrics" },
            };

            // Pass the System Signing CA cert so its SPKI SHA-256 is stored on
            // the Keystores rows and future keystore loads pin-verify the file signature.
            BootstrapKeystoreWriter.WriteCertsToKeystore(keystorePasswords, secondaryPasses, keystoreEntries, sysPrivKey, dbContext, signedSysCert);

            // Generate backup encryption key
            var backupKeyPath = Path.Combine(configDir, "backup.key");
            if (!File.Exists(backupKeyPath))
            {
                var backupKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32); // 256-bit key
                File.WriteAllBytes(backupKeyPath, backupKey);
                FileSecurityUtil.SetOwnerOnly(backupKeyPath);
                Console.WriteLine("✓ Backup encryption key generated");
            }

            // === Store Certificates in DB ===
            // The TSA child cert was signed BEFORE any DB persistence in order to
            // bundle its key into the keystore writes above. Persist the CA + TSA DB rows here
            // in one pass so they are adjacent to each other — if any of these SaveChanges calls
            // fail, the entire bootstrap is aborted (the caller of this method wraps the work in
            // a try/catch that re-throws on failure and the DbContext is dropped on return).
            var kwPassphrase = System.Text.Encoding.UTF8.GetBytes(secondaryPasses["ca-certs.keystore"]);
            var rootCaEntry = BootstrapCertCreator.CreateCertificateEntry(dbContext, caCertPem, signedCaCert, caPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, signingProfile, kwPassphrase);
            // The system signing CA is issued by the root, so its
            // IssuerCertificateId FK points at rootCaEntry.CertificateId.
            BootstrapCertCreator.CreateCertificateEntry(dbContext, sysCertPem, signedSysCert, sysPrivateKeyDer, RootCaStandardOidsJson, RootCaExtendedOidsJson, caCertProfile, signingProfile, kwPassphrase, issuerCertificateId: rootCaEntry.CertificateId);

            // Update signing profile issuer now that the root CA entry exists
            signingProfile.Issuer = rootCaEntry;
            signingProfile.IssuerId = rootCaEntry.CertificateId;
            dbContext.SaveChanges();

            // === Non-CA Certificate Profile ===
            var allowedCertStandardOids = new[] { "Digital Signature", "Key Encipherment" };
            BootstrapProfileSeeder.CreateCertProfile(dbContext, "Main Certificate Profile", "Default cert profile for non-CA certificates",
                allowedCertStandardOids, allowedCertExtendedOids, false, false,
                KeyAlgorithmsJson, KeySizesJson, SignatureAlgorithmsJson, "P47D", "P397D");
            var nonCaCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Main Certificate Profile");
            BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, nonCaCertProfile, signingProfile);

            // Seed infrastructure cert profiles (TSA, OCSP) and link to signing profile
            BootstrapProfileSeeder.SeedInfrastructureCertProfiles(dbContext);
            var tsaCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "TSA Certificate Profile");
            var ocspCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "OCSP Responder Certificate Profile");
            var webTlsCertProfile = BootstrapProfileSeeder.GetCertProfileFromDb(dbContext, "Web TLS Certificate Profile");
            BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, tsaCertProfile, signingProfile);
            BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, ocspCertProfile, signingProfile);
            BootstrapProfileSeeder.LinkCertProfileToSigningProfile(dbContext, webTlsCertProfile, signingProfile);

            BootstrapProfileSeeder.AddFeatureFlagsToDb(dbContext, defaultFlags);

            // === IP Whitelist defaults ===
            BootstrapProfileSeeder.SeedWhitelists(dbContext);

            var caCertEntity = BootstrapCertCreator.GetCertificateFromDb(dbContext, signedCaCert.SubjectDN.ToString());
            var sysCertEntity = BootstrapCertCreator.GetCertificateFromDb(dbContext, signedSysCert.SubjectDN.ToString());

            BootstrapCertCreator.CreateCrlSchedule(dbContext, caCertEntity);
            BootstrapCertCreator.CreateCrlSchedule(dbContext, sysCertEntity);

            BootstrapKeystoreWriter.WriteKeystorePasswordsToFile(configDir, keystorePasswords, keystoreFilePasswords);

            BootstrapCertCreator.CreateCertificateAuthority(dbContext, caCertEntity, type: "Root", isDefault: true, tenantId: orgTenant.Id);
            BootstrapCertCreator.CreateCertificateAuthority(dbContext, sysCertEntity, type: "Root", isDefault: false, label: "system-signing-ca", tenantId: systemTenant.Id);

            var caCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, caCertEntity.CertificateId);
            var sysCertCaEntity = BootstrapCertCreator.GetCertificateAuthorityFromDb(dbContext, sysCertEntity.CertificateId);

            // === CA-Scoped Groups ===
            BootstrapProfileSeeder.CreateCaGroups(dbContext, caCertCaEntity, orgTenant.Id);
            BootstrapProfileSeeder.CreateCaGroups(dbContext, sysCertCaEntity, systemTenant.Id);

            // === Backfill tenant IDs ===
            var unassignedCas = dbContext.CertificateAuthorities
                .Where(ca => ca.TenantId == Guid.Empty)
                .ToList();
            foreach (var ca in unassignedCas)
            {
                ca.TenantId = ca.Label == "system-signing-ca" ? systemTenant.Id : orgTenant.Id;
            }
            if (unassignedCas.Count > 0)
                dbContext.SaveChanges();

            var unassignedGroups = dbContext.CaGroups
                .Where(g => g.TenantId == Guid.Empty)
                .ToList();
            foreach (var group in unassignedGroups)
            {
                if (group.IsSystemGroup)
                    group.TenantId = systemTenant.Id;
                else if (group.CertificateAuthorityId != null)
                {
                    var ownerCa = dbContext.CertificateAuthorities.FirstOrDefault(ca => ca.Id == group.CertificateAuthorityId);
                    group.TenantId = ownerCa?.TenantId ?? orgTenant.Id;
                }
                else
                    group.TenantId = orgTenant.Id;
            }
            if (unassignedGroups.Count > 0)
                dbContext.SaveChanges();

            // mTLS signing is only available on org-tenant groups AND must point at a
            // non-system, non-Root issuing/intermediate CA. Bootstrap clears any legacy
            // mTLS assignment on system groups (handles upgrade-in-place) but does NOT
            // auto-assign one on org groups — admins configure it via the admin UI once
            // they've created an issuing CA under the Root. Root CAs don't sign
            // end-entity certs directly.
            foreach (var systemGroup in dbContext.CaGroups.Where(g => g.IsSystemGroup && g.MtlsSigningCaId != null))
                systemGroup.MtlsSigningCaId = null;
            dbContext.SaveChanges();

            // === Seed request profiles and per-CA protocol configs ===
            var requestProfiles = BootstrapProfileSeeder.SeedDefaultRequestProfiles(dbContext);
            BootstrapProfileSeeder.SeedProtocolConfigs(dbContext, caCertCaEntity, signingProfile, nonCaCertProfile, requestProfiles);
            // System CA: every protocol hardcoded disabled. Belt-and-suspenders alongside
            // ReservedCaLabelGuardMiddleware; even if the guard is lifted, the DB row says "off".
            BootstrapProfileSeeder.SeedSystemCaProtocolConfigs(dbContext, sysCertCaEntity);

            // Auto-generate service URLs — use explicit Network.PublicDomain if provided,
            // otherwise derive from the cert's DNS SANs as a fallback. PublicDomain and ports
            // are network-deployment concerns, owned by SetupNetwork.
            // Shares its derivation with the CLI — see BootstrapServiceUrlBuilder. The SAN fallback
            // here dropped the port (giving port 80 against a listener on 8080) and the
            // no-domain fallback aimed plain HTTP at the HTTPS port; the builder does neither.
            var publicBaseUrl = BootstrapServiceUrlBuilder.Build(
                publicDomain: request.Network.PublicDomain,
                dnsSans: request.WebTlsCertificate.Sans,
                httpPort: request.Network.HttpPublicPort ?? request.Network.HttpPort);

            if (publicBaseUrl == null)
            {
                // The operator set the HTTP port to 0, which the wizard offers and Kestrel honours.
                // Publishing "http://host:0" was the old behaviour and is worse than publishing
                // nothing, because a CDP that cannot be fetched fails revocation checking outright.
                warnings.Add(
                    "Plain HTTP is disabled (HTTP port 0), so no CRL, OCSP or AIA URL was published. " +
                    "Certificates will be issued without a distribution point. Set an HTTP port and " +
                    "re-run setup, or add service URLs for this CA afterwards, to publish one.");
            }
            else
            {
                BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, caCertEntity, publicBaseUrl, caCertCaEntity.Label ?? "default");
                BootstrapProfileSeeder.SeedCaServiceUrls(dbContext, sysCertEntity, publicBaseUrl, sysCertCaEntity.Label ?? "system-signing-ca");
            }

            BootstrapProfileSeeder.SeedPasswordPolicy(dbContext);
            BootstrapProfileSeeder.SeedSecurityPolicy(
                dbContext,
                request.Security?.MaxFailedLoginAttempts,
                request.Security?.LockoutMinutes);
            BootstrapProfileSeeder.SeedLdapPublisherPolicy(dbContext);
            BootstrapProfileSeeder.SeedProtocolRateLimits(dbContext);
            BootstrapProfileSeeder.SeedDefaultSshProfiles(dbContext);
            BootstrapProfileSeeder.SeedNotificationPreferences(dbContext);

            // === Create initial admin user ===
            var adminUsername = string.IsNullOrWhiteSpace(request.Admin.Username) ? "superadmin" : request.Admin.Username;
            var adminEmail = request.Admin.Email;
            var adminPassword = !string.IsNullOrWhiteSpace(request.Admin.Password)
                ? CreateInitialUserWithPassword(dbContext, adminUsername, request.Admin.Password, adminEmail)
                : CreateInitialUserWithUsername(dbContext, adminUsername, adminEmail);

            caCertEntity.CertificateAuthority = caCertCaEntity;
            sysCertEntity.CertificateAuthority = sysCertCaEntity;
            dbContext.SaveChanges();

            if (dbConnection.State == ConnectionState.Open)
                dbConnection.Close();

            // ── Web TLS certificate profile resolution ──────────────────────────────
            // The Web TLS cert is issued using:
            //   • Request profile: the seeded "Web TLS (Internal)" profile — purpose-built for
            //                      the management-UI cert. Permits O/OU/L/ST/C because the
            //                      operator's own root CA is the validation authority, unlike
            //                      "Web Server (ACME)" which (correctly) forbids those fields
            //                      for public DV enrollment per CABF BR §7.1.4.2.2.
            //   • Cert profile:    "Main Certificate Profile" (non-CA leaf profile)
            //   • Signing profile: the signing profile bound to the non-system (user-created) CA
            // The operator's wizard input is validated against the request profile's SubjectDnRules
            // and SanRules before issuance so they fail fast if they picked a CN/SAN that violates
            // the enrollment policy.
            var webTlsRequestProfile = dbContext.RequestProfiles
                .FirstOrDefault(rp => rp.Name == "Web TLS (Internal)")
                ?? throw new InvalidOperationException(
                    "Seed profile 'Web TLS (Internal)' not found — cannot issue Web TLS certificate.");

            var mainCertProfile = dbContext.CertProfiles
                .FirstOrDefault(cp => cp.Name == "Main Certificate Profile")
                ?? throw new InvalidOperationException(
                    "Seed profile 'Main Certificate Profile' not found — cannot issue Web TLS certificate.");

            // Non-system CA = the user-created root CA (everything except the label "system-signing-ca").
            // Prefer the one marked IsDefault when there are multiple candidates.
            var nonSystemCa = dbContext.CertificateAuthorities
                .Where(ca => ca.Label != "system-signing-ca")
                .OrderByDescending(ca => ca.IsDefault)
                .FirstOrDefault()
                ?? throw new InvalidOperationException(
                    "No non-system CA found — cannot resolve a Web TLS signing profile.");

            // Resolve the signing profile bound to that CA. SigningProfileEntity.IssuerId references
            // the CA's CertificateEntity, so we match on that. Fall back to the protocol-config default
            // for ACME if an IssuerId match doesn't turn one up.
            var webTlsSigningProfile = dbContext.SigningProfiles
                .FirstOrDefault(sp => sp.IssuerId == nonSystemCa.CertificateId);
            if (webTlsSigningProfile == null)
            {
                var acmeProtocolConfig = dbContext.CaProtocolConfigs
                    .FirstOrDefault(pc => pc.CaId == nonSystemCa.Id && pc.Protocol == "ACME");
                if (acmeProtocolConfig?.SigningProfileId != null)
                {
                    webTlsSigningProfile = dbContext.SigningProfiles
                        .FirstOrDefault(sp => sp.Id == acmeProtocolConfig.SigningProfileId);
                }
            }
            if (webTlsSigningProfile == null)
                throw new InvalidOperationException(
                    $"CA '{nonSystemCa.Name}' has no resolvable signing profile — cannot issue Web TLS certificate.");

            // Build the subject DN and SAN list from the wizard input, then validate against
            // the ACME request profile's SubjectDnRules / SanRules before issuing.
            var webTlsRequest = request.WebTlsCertificate;
            var subjectDnParts = new List<string>();
            if (!string.IsNullOrWhiteSpace(webTlsRequest.CommonName))
                subjectDnParts.Add($"CN={webTlsRequest.CommonName}");
            if (!string.IsNullOrWhiteSpace(webTlsRequest.OrganizationalUnit))
                subjectDnParts.Add($"OU={webTlsRequest.OrganizationalUnit}");
            if (!string.IsNullOrWhiteSpace(webTlsRequest.Organization))
                subjectDnParts.Add($"O={webTlsRequest.Organization}");
            if (!string.IsNullOrWhiteSpace(webTlsRequest.Locality))
                subjectDnParts.Add($"L={webTlsRequest.Locality}");
            if (!string.IsNullOrWhiteSpace(webTlsRequest.State))
                subjectDnParts.Add($"ST={webTlsRequest.State}");
            if (!string.IsNullOrWhiteSpace(webTlsRequest.Country))
                subjectDnParts.Add($"C={webTlsRequest.Country}");
            var subjectDn = string.Join(",", subjectDnParts);

            var sansJson = JsonSerializer.Serialize(webTlsRequest.Sans ?? new List<string>());

            // RequestProfileValidationService now resolves the request profile through the
            // inheritance clamp rather than reading the raw row, so it needs the resolution
            // service. Bootstrap has no DI container, so construct it directly.
            var validationService = new RequestProfileValidationService(
                dbContext,
                new ProfileResolutionService(
                    dbContext,
                    Microsoft.Extensions.Logging.Abstractions.NullLogger<ProfileResolutionService>.Instance));
            var (isValid, validationError, normalizedDn) = validationService
                .ValidateAsync(webTlsRequestProfile.Id, subjectDn, sansJson)
                .GetAwaiter()
                .GetResult();
            if (!isValid)
                throw new InvalidOperationException(
                    $"Web TLS certificate inputs failed 'Web TLS (Internal)' request profile validation: {validationError}");

            // Use the normalized DN returned by the validator when available — it may have fixed
            // values applied or defaults filled in per the request profile rules.
            var effectiveSubjectDn = !string.IsNullOrWhiteSpace(normalizedDn) ? normalizedDn! : subjectDn;

            // === Store TSA signer certificate in DB ===
            BootstrapCertCreator.StoreTsaCertificate(signedTsaCert, tsaKeyPair, dbContext, signingProfile, nonCaCertProfile, caCertCaEntity);

            // === Store OCSP responder certificate in DB ===
            BootstrapCertCreator.StoreOcspResponderCertificate(signedOcspCert, ocspKeyPair, dbContext, signingProfile, nonCaCertProfile, caCertCaEntity);

            // === Build pending web TLS config for Stage 2 provisioning ===
            var pendingSubjectDn = effectiveSubjectDn;
            var pendingSans = webTlsRequest.Sans ?? new List<string>();
            var pendingValidityDays = webTlsRequest.ValidityDays;

            // === Create dedicated MySQL users and generate config.yaml ===
            // Preserve audit history unless the operator ticked the wipe box in the wizard.
            var (appUserPassword, auditUserPassword) = BootstrapDatabaseSetup.CreateDatabaseUsers(
                rootConfig, setupDbConfig, request.Database?.WipeAuditDatabase ?? false);

            // === Apply audit database migrations using root credentials ===
            BootstrapModularCA.CreateAuditDatabase(rootConfig, setupDbConfig.SqlAudit.Database);

            BootstrapDatabaseSetup.WriteConfigFile(configDir, rootConfig, setupDbConfig, bootstrapConfig, appUserPassword, auditUserPassword,
                pfxPassword: "", // No PFX yet — Stage 2 generates it
                httpsPort: request.Network.HttpsPort,
                httpPort: request.Network.HttpPort,
                publicDomain: request.Network.PublicDomain,
                httpsPublicPort: request.Network.HttpsPublicPort ?? request.Network.HttpsPort,
                httpPublicPort: request.Network.HttpPublicPort ?? request.Network.HttpPort,
                security: request.Security,
                network: request.Network,
                pendingSubjectDn: pendingSubjectDn,
                pendingSans: pendingSans,
                pendingValidityDays: pendingValidityDays,
                pendingKeyAlgorithm: webTlsRequest.KeyAlgorithm,
                pendingKeySize: webTlsRequest.KeySize);

            // === Write db.yaml with generated app credentials ===
            var dbYamlPath = Path.Combine(configDir, "db.yaml");
            var (appUser, _) = BootstrapDatabaseSetup.ResolveMysqlUser(setupDbConfig.SqlApp.Username, rootConfig.Host);
            var (auditUser, _) = BootstrapDatabaseSetup.ResolveMysqlUser(setupDbConfig.SqlAudit.Username, rootConfig.Host);
            YamlDbConfigLoader.Write(dbYamlPath, new YamlDbConfigLoader.DbYamlConfig
            {
                App = new YamlDbConfigLoader.DbInstanceConfig
                {
                    Host = rootConfig.Host,
                    Port = rootConfig.Port,
                    Database = setupDbConfig.SqlApp.Database,
                    Username = appUser,
                    Password = appUserPassword,
                    // Propagate the operator-selected TLS mode into
                    // db.yaml so runtime app/audit connections honor the same policy.
                    SslMode = selectedSslModeString
                },
                Audit = new YamlDbConfigLoader.DbInstanceConfig
                {
                    Host = rootConfig.Host,
                    Port = rootConfig.Port,
                    Database = setupDbConfig.SqlAudit.Database,
                    Username = auditUser,
                    Password = auditUserPassword,
                    SslMode = selectedSslModeString
                }
            });

            // === Copy baseline policy files ===
            SeedPolicyFiles(configDir);

            // ICF-10: Delete setup-database.yaml — root credentials are no longer needed
            // after bootstrap creates the dedicated app/audit MySQL users.
            var setupDbPath = Path.Combine(configDir, "setup-database.yaml");
            if (File.Exists(setupDbPath))
            {
                File.Delete(setupDbPath);
                Console.WriteLine("✓ setup-database.yaml deleted (root credentials no longer needed).");
            }

            // Promote the freshly-seeded whitelist rules from the DB into the live IWhitelistService snapshot.
            // Without this, the service stays on the pre-bootstrap hardcoded fallback until the next app restart.
            if (serviceProvider != null)
            {
                try
                {
                    var whitelistService = serviceProvider.GetService<IWhitelistService>();
                    if (whitelistService != null)
                    {
                        whitelistService.ReloadAsync().GetAwaiter().GetResult();
                        Console.WriteLine("✓ IWhitelistService snapshot reloaded from seeded rules.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"(!) IWhitelistService reload failed: {ex.Message} — service will refresh on next app restart.");
                }
            }

            return new SetupResponse
            {
                Success = true,
                Message = "ModularCA setup completed successfully.",
                AdminUsername = adminUsername,
                AdminPassword = adminPassword,
                Warnings = warnings
            };
        }
        catch (Exception ex)
        {
            // Log the full exception server-side only.
            // Do NOT include exception detail in the SetupResponse returned to the wizard —
            // the SPA renders Message verbatim and the raw exception often contains the
            // connection string (root DB password) and admin-password material. Return a
            // stable correlation id instead; operators look up the full stack in Serilog.
            var correlationId = Guid.NewGuid().ToString("N").Substring(0, 12);
            Serilog.Log.Error(ex,
                "Bootstrap setup failed (correlationId={CorrelationId})", correlationId);
            return new SetupResponse
            {
                Success = false,
                Message = $"Setup failed — check server logs (correlationId={correlationId})",
                Warnings = warnings
            };
        }
    }

    /// <summary>
    /// Maps a <see cref="SetupRequest"/> to the <see cref="YamlBootstrapLoader.BootstrapConfig"/>
    /// format expected by the existing bootstrap helper methods.
    /// Database credentials are handled separately via <see cref="YamlSetupDatabaseLoader.SetupDatabaseConfig"/>.
    /// </summary>
    private static YamlBootstrapLoader.BootstrapConfig MapToBootstrapConfig(SetupRequest request)
    {
        return new YamlBootstrapLoader.BootstrapConfig
        {
            CA = new YamlBootstrapLoader.CaConfig
            {
                Algorithm = SetupKeySizeParser.ResolveAlgorithm(request.RootCa.Algorithm, request.RootCa.KeySize),
                KeySize = SetupKeySizeParser.ParseToInt(request.RootCa.Algorithm, request.RootCa.KeySize),
                ValidityYears = request.RootCa.ValidityYears,
                Subject = new YamlBootstrapLoader.CaSubjectConfig
                {
                    CN = request.RootCa.CommonName,
                    O = request.RootCa.Organization,
                    OU = !string.IsNullOrWhiteSpace(request.RootCa.OrganizationalUnit) ? new List<string> { request.RootCa.OrganizationalUnit } : null,
                    L = request.RootCa.Locality,
                    ST = request.RootCa.State,
                    C = request.RootCa.Country
                }
            },
            Features = new YamlBootstrapLoader.FeaturesConfig
            {
                CRL = request.Features.Crl,
                OCSP = request.Features.Ocsp,
                ACME = request.Features.Acme,
                EST = request.Features.Est,
                SCEP = request.Features.Scep,
                CMP = request.Features.Cmp,
                MSAE = request.Features.Msae
            },
            HttpsApi = new YamlBootstrapLoader.HttpsApiConfig
            {
                CN = request.WebTlsCertificate.CommonName,
                SANs = request.WebTlsCertificate.Sans,
                Port = request.Network.HttpsPort,
                ValidityDays = request.WebTlsCertificate.ValidityDays
            }
        };
    }

    /// <summary>
    /// Creates the initial admin user with the specified username and a generated password.
    /// Returns the generated password for display to the administrator.
    /// </summary>
    private static string CreateInitialUserWithUsername(ModularCADbContext db, string username, string? email = null)
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
                throw new InvalidOperationException("Failed to generate a password meeting policy after 100 attempts.");
        }
        while (!BootstrapProfileSeeder.MeetsPolicy(password, policy));

        var initialUser = new UserEntity
        {
            Username = username,
            Email = email ?? string.Empty,
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

        // Assign to system-super group
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
            .Where(g => g.Grants.Any(gr => gr.Capability == Shared.Authorization.Capabilities.CaManage) && !g.IsSystemGroup)
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

        return password;
    }

    /// <summary>
    /// Creates the initial admin user with a user-provided password (from the setup wizard).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the supplied password does not satisfy the password policy seeded moments
    /// earlier by <c>SeedPasswordPolicy</c>.
    /// </exception>
    private static string CreateInitialUserWithPassword(ModularCADbContext db, string username, string password, string? email = null)
    {
        // Validate against the same policy the generated-password path loops on. Without this
        // the wizard's admin password was checked NOWHERE on the server: setupui validates in
        // the browser only, and anyone can POST the setup request directly. The most privileged
        // account in the install could therefore be created with a one-character password, while
        // every subsequent password change was policy-enforced.
        var policy = db.PasswordPolicies.FirstOrDefault() ?? new PasswordPolicyEntity();
        if (!BootstrapProfileSeeder.MeetsPolicy(password, policy))
        {
            throw new InvalidOperationException(
                "The administrator password does not meet the configured password policy " +
                $"(minimum length {policy.MinLength}" +
                (policy.RequireUppercase ? ", uppercase" : string.Empty) +
                (policy.RequireLowercase ? ", lowercase" : string.Empty) +
                (policy.RequireDigit ? ", digit" : string.Empty) +
                (policy.RequireSymbol ? ", symbol" : string.Empty) +
                "). Choose a stronger password and run setup again.");
        }

        var initialUser = new UserEntity
        {
            Username = username,
            Email = email ?? string.Empty,
            PasswordHash = ModularCA.Auth.Utils.PasswordUtil.HashPassword(password),
            CreatedAt = DateTime.UtcNow,
        };
        db.Users.Add(initialUser);
        db.SaveChanges();

        // Assign to system-super group
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
            .Where(g => g.Grants.Any(gr => gr.Capability == Shared.Authorization.Capabilities.CaManage) && !g.IsSystemGroup)
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

        return password;
    }

    /// <summary>
    /// Copies baseline policy YAML files from .yaml.example templates if the active files don't exist yet.
    /// </summary>
    private static void SeedPolicyFiles(string configDir)
    {
        var policiesDir = Path.Combine(configDir, "policies");
        Directory.CreateDirectory(policiesDir);

        var policyFiles = new[] { "cert-profiles.yaml", "signing-profiles.yaml", "request-profiles.yaml" };
        foreach (var fileName in policyFiles)
        {
            var targetPath = Path.Combine(policiesDir, fileName);
            if (File.Exists(targetPath))
                continue;

            var examplePath = Path.Combine(policiesDir, $"{fileName}.example");
            if (!File.Exists(examplePath))
                examplePath = Path.Combine(AppContext.BaseDirectory, "config", "policies", $"{fileName}.example");

            if (File.Exists(examplePath))
                File.Copy(examplePath, targetPath);
        }
    }
}
