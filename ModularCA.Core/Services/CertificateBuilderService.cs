using Microsoft.Extensions.Logging;
using ModularCA.Keystore.Adapters;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Net;
using System.Text.Json;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Builds signed X.509 certificates using BouncyCastle. Takes validated issuance parameters,
    /// constructs the certificate with all required extensions (BasicConstraints, SKI, AKI,
    /// KeyUsage, EKU, SANs, CDP, AIA, policies), and signs with the CA key.
    /// </summary>
    public class CertificateBuilderService
    {
        private readonly ICaServiceUrlService _caServiceUrlService;
        private readonly ILogger<CertificateBuilderService> _logger;

        /// <summary>
        /// Initializes a new instance of <see cref="CertificateBuilderService"/>.
        /// </summary>
        /// <param name="caServiceUrlService">Service for resolving AIA and CDP URLs per CA.</param>
        /// <param name="logger">Logger instance.</param>
        public CertificateBuilderService(ICaServiceUrlService caServiceUrlService, ILogger<CertificateBuilderService> logger)
        {
            _caServiceUrlService = caServiceUrlService;
            _logger = logger;
        }

        /// <summary>
        /// Builds and signs an X.509 certificate using the provided parameters.
        /// Adds all standard extensions: BasicConstraints (with path length from signing profile for CA certs),
        /// SKI, AKI, KeyUsage, EKU, SANs, CDP, AIA, and policies.
        /// </summary>
        /// <param name="serialNumber">The serial number for the new certificate.</param>
        /// <param name="issuerCert">The issuing CA certificate.</param>
        /// <param name="caKeyHandle">The CA's private key handle (supports HSM).</param>
        /// <param name="subjectDn">The subject distinguished name.</param>
        /// <param name="subjectPublicKey">The subject's public key from the CSR.</param>
        /// <param name="validFrom">The NotBefore date.</param>
        /// <param name="validTo">The NotAfter date.</param>
        /// <param name="standardOids">Resolved standard key usage friendly names.</param>
        /// <param name="extendedOids">Resolved extended key usage OID strings.</param>
        /// <param name="subjectAlternativeNames">JSON array of SANs (e.g. ["DNS:example.com"]).</param>
        /// <param name="caCertificateId">The CA certificate ID for CDP/AIA lookup.</param>
        /// <param name="signingProfile">The signing profile for policy extensions.</param>
        /// <param name="isCa">Whether the certificate being issued is a CA certificate (controls BasicConstraints and path length).</param>
        /// <returns>The signed <see cref="X509Certificate"/>.</returns>
        public async Task<X509Certificate> BuildCertificateAsync(
            BigInteger serialNumber,
            X509Certificate issuerCert,
            IPrivateKeyHandle caKeyHandle,
            X509Name subjectDn,
            AsymmetricKeyParameter subjectPublicKey,
            DateTime validFrom,
            DateTime validTo,
            List<string> standardOids,
            List<string> extendedOids,
            string? subjectAlternativeNames,
            Guid caCertificateId,
            SigningProfileEntity? signingProfile,
            bool isCa = false,
            bool allowWildcardSans = false)
        {
            // Defensive assertion — when the key handle is software-backed
            // and exportable, derive the corresponding public key and compare against
            // the issuer cert's public key. Mismatch means the caller wired the wrong
            // (issuer cert, CA key) pair and the AKI we emit would point at a key that
            // did not sign the certificate. HSM-backed (non-exportable) handles can't
            // be cross-checked this way, so they're trusted — callers for HSM keys are
            // expected to be thin resolvers that look both up from the same row.
            var issuerPublicKey = issuerCert.GetPublicKey();
            if (caKeyHandle.CanExport)
            {
                // Zero the DER transport buffer as soon as BC has consumed it.
                // This assertion derives the CA public key from the exported private key to
                // cross-check the caller-supplied issuer cert. For HSM handles the check is
                // skipped (CanExport == false); the signing itself still goes through the
                // handle's Sign(...) API via PrivateKeyHandleSignatureFactory below.
                AsymmetricKeyParameter? derivedPub = null;
                var derBytes = caKeyHandle.ExportPrivateKeyDer();
                try
                {
                    var derivedPriv = Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(derBytes);
                    derivedPub = DerivePublicKey(derivedPriv);
                }
                catch
                {
                    // Best-effort: if derivation fails for this key type, let the signer
                    // catch any real mismatch downstream rather than blocking issuance.
                }
                finally
                {
                    if (derBytes != null)
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(derBytes);
                }
                if (derivedPub != null && !issuerPublicKey.Equals(derivedPub))
                {
                    throw new InvalidOperationException(
                        "Issuer certificate public key does not match CA key handle public key. " +
                        "Refusing to sign to avoid producing a certificate whose AKI points at a key that did not sign it.");
                }
            }

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(issuerCert.SubjectDN);
            certGen.SetSubjectDN(subjectDn);
            // Normalize the Kind before handing these to BouncyCastle. SetNotBefore/SetNotAfter
            // call ToUniversalTime(), which for a DateTimeKind.Unspecified value assumes LOCAL time
            // and adds the host's UTC offset. Requested windows are read back from MySQL by EF as
            // Unspecified, so an issuance that honoured the window recorded on the request produced
            // a certificate that was not valid until now-plus-the-server-offset — six hours on the
            // affected host, rejected by every relying party until then.
            certGen.SetNotBefore(CertificateValidityUtil.AsUtc(validFrom));
            certGen.SetNotAfter(CertificateValidityUtil.AsUtc(validTo));
            certGen.SetPublicKey(subjectPublicKey);

            // === Extensions ===

            // BasicConstraints — CA certificate with optional path length, or leaf
            if (isCa)
            {
                if (signingProfile?.MaxPathLength != null && signingProfile.MaxPathLength >= 0)
                {
                    certGen.AddExtension(X509Extensions.BasicConstraints, true,
                        new BasicConstraints(signingProfile.MaxPathLength.Value));
                }
                else
                {
                    certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
                }
            }
            else
            {
                certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            }

            // Subject Key Identifier (hash of the leaf cert's public key)
            var leafPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublicKey);
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(leafPublicKeyInfo));

            // Authority Key Identifier (hash of the CA's public key — links leaf to CA)
            var caPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerPublicKey);
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPublicKeyInfo));

            // KeyUsage — fails closed on unknown friendly names via the shared helper.
            int usageFlags = 0;
            if (standardOids.Count != 0)
            {
                usageFlags = KeyUsageFriendlyNames.ParseMany(standardOids);
            }

            // When building a CA certificate, always normalise in keyCertSign and cRLSign.
            // These bits are MANDATORY on any BasicConstraints.cA=TRUE certificate (RFC 5280
            // §4.2.1.3) — a CA cert without keyCertSign makes every chain it signs fail path
            // validation. Adding them is therefore by-design correctness, not an error: a CA
            // profile that simply doesn't restate the implied CA bits (or has them intersected
            // away by restrictive profile inheritance) is still valid, and the cert is always
            // built correctly. Logged at debug only so this expected normalisation doesn't emit
            // a misleading warning on every single CA creation.
            if (isCa)
            {
                var requiredCaBits = KeyUsage.KeyCertSign | KeyUsage.CrlSign;
                var missing = requiredCaBits & ~usageFlags;
                if (missing != 0)
                {
                    _logger.LogDebug(
                        "Normalising mandatory CA key usages onto CA certificate (added mask 0x{Missing:X}: keyCertSign/cRLSign per RFC 5280 §4.2.1.3).",
                        missing);
                }
                usageFlags |= requiredCaBits;
            }

            if (usageFlags != 0)
            {
                certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(usageFlags));
            }

            // Subject Alternative Names — strict prefix-split, one switch per type,
            // hard error on unknown/unsupported types. Replaces the old Contains()
            // classifier that silently dropped URI / EMAIL / RID / DirName entries.
            if (!string.IsNullOrWhiteSpace(subjectAlternativeNames))
            {
                var sanList = JsonSerializer.Deserialize<List<string>>(subjectAlternativeNames, SafeJsonOptions.Default);
                if (sanList != null && sanList.Count > 0)
                {
                    var sanNames = new List<GeneralName>();
                    foreach (var entry in sanList)
                    {
                        if (string.IsNullOrWhiteSpace(entry)) continue;
                        var idx = entry.IndexOf(':');
                        if (idx < 1)
                            throw new InvalidOperationException(
                                $"SAN entry '{entry}' is missing a TYPE:value prefix (expected DNS:, IP:, URI:, EMAIL:).");
                        var type = entry[..idx].Trim().ToUpperInvariant();
                        var value = entry[(idx + 1)..].Trim();

                        switch (type)
                        {
                            case "DNS":
                                DnComponentSanitizer.ValidateDnsName(value, allowWildcardSans);
                                sanNames.Add(SanGeneralNames.Build(type, value));
                                break;
                            case "IP":
                                var ipValue = value;
                                // BouncyCastle stores IP SANs as hex-encoded DER octets (e.g. "#0a090d01").
                                // Convert to dotted-decimal / colon-hex notation for re-encoding.
                                if (ipValue.StartsWith('#') && (ipValue.Length == 9 || ipValue.Length == 33))
                                {
                                    var hexBytes = Convert.FromHexString(ipValue[1..]);
                                    ipValue = new IPAddress(hexBytes).ToString();
                                }
                                if (!IPAddress.TryParse(ipValue, out _))
                                    throw new InvalidOperationException($"IP SAN '{value}' is not a valid IP literal.");
                                sanNames.Add(SanGeneralNames.Build(type, ipValue));
                                break;
                            case "URI":
                                DnComponentSanitizer.ValidateUri(value);
                                sanNames.Add(SanGeneralNames.Build(type, value));
                                break;
                            case "EMAIL":
                            case "RFC822":
                                DnComponentSanitizer.ValidateEmail(value);
                                sanNames.Add(SanGeneralNames.Build(type, value));
                                break;
                            case "UPN":
                                // Microsoft otherName (1.3.6.1.4.1.311.20.2.3). This is the name
                                // Windows maps a smart-card logon certificate to an Active
                                // Directory account by, so it is an identity claim rather than a
                                // network name — see UpnSanEncoding and ValidateUpn.
                                DnComponentSanitizer.ValidateUpn(value);
                                sanNames.Add(SanGeneralNames.Build(type, value));
                                break;
                            default:
                                throw new InvalidOperationException(
                                    $"Unsupported SAN type '{type}' in entry '{entry}'. " +
                                    $"Supported types: {SanGeneralNames.SupportedTypes}.");
                        }
                    }
                    if (sanNames.Count > 0)
                    {
                        var sanBuilder = new GeneralNames(sanNames.ToArray());
                        certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, sanBuilder);
                    }
                }
            }

            // ExtendedKeyUsage — anyExtendedKeyUsage (2.5.29.37.0) is explicitly filtered out
            // in IssuanceValidationService.SetupAllowedExtendedOids, so by the time we get here
            // the list is already safe. Criticality is sourced from the signing profile's
            // ExtendedKeyUsageCritical flag (RFC 5280 §4.2.1.12 recommends critical when the
            // cert's purpose is restricted). Default false for backwards compat.
            bool hasOcspSigningEku = false;
            if (extendedOids.Count != 0)
            {
                var usages = extendedOids.Select(u => new DerObjectIdentifier(u)).ToList();
                var ekuCritical = signingProfile?.ExtendedKeyUsageCritical ?? false;
                certGen.AddExtension(X509Extensions.ExtendedKeyUsage, ekuCritical, new ExtendedKeyUsage(usages));
                hasOcspSigningEku = extendedOids.Contains("1.3.6.1.5.5.7.3.9");
            }

            // Any cert carrying id-kp-OCSPSigning EKU must
            // also carry id-pkix-ocsp-nocheck (OID 1.3.6.1.5.5.7.48.1.5, non-
            // critical, NULL value) per RFC 6960 §4.2.2.2.1 so relying parties
            // don't loop back to the same responder to revocation-check it.
            // Emit unconditionally — even if the operator didn't ask for it,
            // it's safe (the extension only applies to responder-signer certs)
            // and correctness is more important than operator intent here.
            if (hasOcspSigningEku)
            {
                certGen.AddExtension(
                    new DerObjectIdentifier("1.3.6.1.5.5.7.48.1.5"),
                    critical: false,
                    extensionValue: DerNull.Instance);
            }

            // CDP and AIA extensions
            await AddCdpAndAiaExtensionsAsync(certGen, caCertificateId);

            // Name constraints, policy, and path length extensions from signing profile
            AddPolicyExtensions(certGen, signingProfile, isCa);

            // === Sign cert (via key handle — supports HSM) ===
            var sigAlgName = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(issuerCert.GetPublicKey()));
            var signer = new PrivateKeyHandleSignatureFactory(sigAlgName, caKeyHandle);
            return certGen.Generate(signer);
        }

        /// <summary>
        /// Resolves the subject DN from a PKCS#10 CSR, falling back to the first DNS SAN
        /// stored on the CSR entity when the CSR itself has an empty subject.
        /// </summary>
        /// <param name="csr">The parsed PKCS#10 certification request.</param>
        /// <param name="csrEntity">The CSR database entity (used for SAN fallback).</param>
        /// <returns>The resolved X509Name for the certificate subject.</returns>
        public X509Name ResolveSubjectDn(Pkcs10CertificationRequest csr, CertRequestEntity csrEntity)
        {
            var csrSubject = csr.GetCertificationRequestInfo().Subject;
            if (csrSubject != null && csrSubject.ToString().Length > 0)
                return csrSubject;

            // CSR has no subject DN (common with ACME/certbot) — default CN to the first DNS SAN
            if (!string.IsNullOrWhiteSpace(csrEntity.SubjectAlternativeNames))
            {
                var sans = JsonSerializer.Deserialize<List<string>>(csrEntity.SubjectAlternativeNames, SafeJsonOptions.Default);
                var firstDns = sans?.FirstOrDefault(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase));
                if (firstDns != null)
                {
                    var dnsValue = firstDns[(firstDns.IndexOf(':') + 1)..].Trim();
                    // Sanitize the default CN derived from a SAN so
                    // control chars / BIDI overrides / over-length SANs can't
                    // seed a hostile subject DN.
                    dnsValue = DnComponentSanitizer.Sanitize("CN", dnsValue, DnComponentSanitizer.CommonNameMaxLength);
                    return new X509Name($"CN={dnsValue}");
                }
            }

            return csrSubject ?? new X509Name("");
        }

        /// <summary>
        /// Adds CRL Distribution Points (CDP) and Authority Information Access (AIA) extensions
        /// to the certificate being generated. Delegates all URL resolution to
        /// <see cref="ICaServiceUrlService.ResolveForCaAsync"/>, which merges the CA's stored
        /// <c>PublicBaseUrl</c> with any custom URL lists — relative entries get prefixed, empty
        /// lists fall back to the standard short-URL pattern (<c>{base}/crl/{label}</c>,
        /// <c>{base}/ocsp</c>, <c>{base}/ca/{label}</c>).
        /// </summary>
        /// <param name="certGen">The certificate generator to add extensions to.</param>
        /// <param name="caCertificateId">The CA certificate ID to look up service URLs for.</param>
        internal async Task AddCdpAndAiaExtensionsAsync(X509V3CertificateGenerator certGen, Guid caCertificateId)
        {
            var resolved = await _caServiceUrlService.ResolveForCaAsync(caCertificateId);

            // Dedupe on each URL list before emitting extension entries
            // so configuration drift between the CA entity and the custom URL list
            // doesn't produce a cert with repeated CDP / AIA entries.
            var cdpUrls = resolved.CdpUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var ocspUrls = resolved.OcspUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var caIssuerUrls = resolved.CaIssuerUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            // CRL Distribution Points (CDP)
            if (cdpUrls.Count > 0)
            {
                var distributionPoints = cdpUrls.Select(url =>
                    new DistributionPoint(
                        new DistributionPointName(
                            new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, url))),
                        null, null))
                    .ToArray();

                certGen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(distributionPoints));
            }

            // Authority Information Access (AIA) — OCSP + CA Issuers
            var accessDescriptions = new List<AccessDescription>();

            foreach (var ocspUrl in ocspUrls)
            {
                accessDescriptions.Add(new AccessDescription(
                    AccessDescription.IdADOcsp,
                    new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl)));
            }

            foreach (var caIssuerUrl in caIssuerUrls)
            {
                accessDescriptions.Add(new AccessDescription(
                    AccessDescription.IdADCAIssuers,
                    new GeneralName(GeneralName.UniformResourceIdentifier, caIssuerUrl)));
            }

            if (accessDescriptions.Count > 0)
            {
                certGen.AddExtension(X509Extensions.AuthorityInfoAccess, false,
                    new AuthorityInformationAccess(accessDescriptions.ToArray()));
            }
        }

        /// <summary>
        /// Adds name constraints, certificate policies, and inhibit-any-policy extensions
        /// from the signing profile configuration.
        /// </summary>
        /// <param name="certGen">The certificate generator to add extensions to.</param>
        /// <param name="profile">The signing profile containing policy configuration.</param>
        /// <param name="isCa">Whether the certificate being issued is a CA certificate.</param>
        private static void AddPolicyExtensions(X509V3CertificateGenerator certGen, SigningProfileEntity? profile, bool isCa)
        {
            if (profile == null) return;

            // NameConstraints (critical) — only for CA certs
            if (isCa && (!string.IsNullOrWhiteSpace(profile.NameConstraintsPermitted)
                      || !string.IsNullOrWhiteSpace(profile.NameConstraintsExcluded)))
            {
                var permitted = ParseSubtrees(profile.NameConstraintsPermitted);
                var excluded = ParseSubtrees(profile.NameConstraintsExcluded);
                if (permitted != null || excluded != null)
                {
                    certGen.AddExtension(X509Extensions.NameConstraints, true,
                        new NameConstraints((IList<GeneralSubtree>?)permitted, (IList<GeneralSubtree>?)excluded));
                }
            }

            // CertificatePolicies — emit one PolicyInformation per OID, optionally with
            // CpsUri and UserNotice qualifier sequences sourced from PolicyQualifiersJson.
            // The qualifiers JSON shape is { "<oid>": { "cpsUri": "...", "userNotice": "...", "critical": false } }.
            // Missing keys mean "no qualifiers, non-critical". The extension itself is marked
            // critical when any per-OID `critical` flag is true.
            if (!string.IsNullOrWhiteSpace(profile.PolicyOids))
            {
                var oids = JsonSerializer.Deserialize<List<string>>(profile.PolicyOids, SafeJsonOptions.Default);
                if (oids != null && oids.Count > 0)
                {
                    var qualifierMap = ParsePolicyQualifiers(profile.PolicyQualifiersJson);
                    var policies = oids.Select(o => BuildPolicyInformation(o, qualifierMap)).ToArray();
                    var critical = qualifierMap.Values.Any(q => q.Critical);
                    certGen.AddExtension(X509Extensions.CertificatePolicies, critical,
                        new CertificatePolicies(policies));
                }
            }

            // InhibitAnyPolicy
            if (profile.InhibitAnyPolicy)
            {
                certGen.AddExtension(X509Extensions.InhibitAnyPolicy, true,
                    new DerInteger(0));
            }
        }

        /// <summary>
        /// Parsed per-OID qualifier metadata for the CertificatePolicies extension. Built from
        /// <see cref="SigningProfileEntity.PolicyQualifiersJson"/> by <see cref="ParsePolicyQualifiers"/>
        /// and consumed by <see cref="BuildPolicyInformation"/>. Named with a "Config" suffix so it
        /// does not collide with BouncyCastle's <c>Org.BouncyCastle.Asn1.X509.PolicyQualifierInfo</c>.
        /// </summary>
        private readonly record struct PolicyQualifierConfig(string? CpsUri, string? UserNotice, bool Critical);

        /// <summary>
        /// Parses the per-OID qualifier metadata stored on the signing profile. Shape:
        /// <c>{ "&lt;oid&gt;": { "cpsUri": "...", "userNotice": "...", "critical": false } }</c>.
        /// Missing keys map to a default "no qualifiers, non-critical" record so callers can
        /// look up any OID safely. Malformed JSON returns an empty map.
        /// </summary>
        private static Dictionary<string, PolicyQualifierConfig> ParsePolicyQualifiers(string? json)
        {
            var result = new Dictionary<string, PolicyQualifierConfig>(StringComparer.Ordinal);
            if (string.IsNullOrWhiteSpace(json)) return result;

            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Object) return result;
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    var oid = prop.Name;
                    var value = prop.Value;
                    string? cpsUri = null;
                    string? userNotice = null;
                    bool critical = false;
                    if (value.ValueKind == JsonValueKind.Object)
                    {
                        if (value.TryGetProperty("cpsUri", out var cpsEl) && cpsEl.ValueKind == JsonValueKind.String)
                            cpsUri = cpsEl.GetString();
                        if (value.TryGetProperty("userNotice", out var unEl) && unEl.ValueKind == JsonValueKind.String)
                            userNotice = unEl.GetString();
                        if (value.TryGetProperty("critical", out var critEl) &&
                            (critEl.ValueKind == JsonValueKind.True || critEl.ValueKind == JsonValueKind.False))
                            critical = critEl.GetBoolean();
                    }
                    result[oid] = new PolicyQualifierConfig(cpsUri, userNotice, critical);
                }
            }
            catch (JsonException)
            {
                // Tolerated: a malformed qualifier blob downgrades to "no qualifiers" rather than
                // failing issuance entirely. The signing-profile editor in the admin UI is the
                // place to validate the JSON shape before persisting.
            }
            return result;
        }

        /// <summary>
        /// Builds a <see cref="PolicyInformation"/> for the given OID, attaching CPS-URI and
        /// UserNotice qualifier sequences when the qualifier map carries them. Returns a
        /// qualifier-less PolicyInformation when no entry exists.
        /// </summary>
        private static PolicyInformation BuildPolicyInformation(string oid, IReadOnlyDictionary<string, PolicyQualifierConfig> qualifiers)
        {
            var policyOid = new DerObjectIdentifier(oid);
            if (!qualifiers.TryGetValue(oid, out var info))
                return new PolicyInformation(policyOid);

            var qualifierList = new List<PolicyQualifierInfo>();
            if (!string.IsNullOrWhiteSpace(info.CpsUri))
            {
                qualifierList.Add(new PolicyQualifierInfo(
                    PolicyQualifierID.IdQtCps,
                    new DerIA5String(info.CpsUri)));
            }
            if (!string.IsNullOrWhiteSpace(info.UserNotice))
            {
                // RFC 5280 §4.2.1.4 UserNotice ::= SEQUENCE { noticeRef OPTIONAL, explicitText OPTIONAL }
                // We only emit explicitText. UTF8String is the modern choice; IA5String is also legal.
                var notice = new UserNotice(null, new DisplayText(DisplayText.ContentTypeUtf8String, info.UserNotice));
                qualifierList.Add(new PolicyQualifierInfo(
                    PolicyQualifierID.IdQtUnotice,
                    notice));
            }

            if (qualifierList.Count == 0)
                return new PolicyInformation(policyOid);

            return new PolicyInformation(policyOid, new DerSequence(qualifierList.ToArray()));
        }

        /// <summary>
        /// Public helper that builds a <see cref="NameConstraints"/> ASN.1 structure from a pair
        /// of JSON arrays in the same format the signing-profile entity uses
        /// (<c>["DNS:.example.com", "IP:10.0.0.0/8", "Email:@example.com"]</c>). Returns
        /// <c>null</c> when both inputs are null/empty so callers can treat the whole
        /// extension as optional. Used by <c>CaCreationService</c> to attach
        /// NameConstraints at CA-creation time, before the per-CA signing profile exists.
        /// </summary>
        /// <param name="permittedJson">JSON array of permitted general-name entries.</param>
        /// <param name="excludedJson">JSON array of excluded general-name entries.</param>
        /// <returns>A populated <see cref="NameConstraints"/> instance, or <c>null</c> if neither input has content.</returns>
        public static NameConstraints? BuildNameConstraints(string? permittedJson, string? excludedJson)
        {
            var permitted = ParseSubtrees(permittedJson);
            var excluded = ParseSubtrees(excludedJson);
            if (permitted == null && excluded == null)
                return null;
            return new NameConstraints((IList<GeneralSubtree>?)permitted, (IList<GeneralSubtree>?)excluded);
        }

        /// <summary>
        /// Parses a JSON array of general name entries (e.g. "DNS:example.com") into GeneralSubtree objects
        /// for use in NameConstraints extensions.
        /// </summary>
        private static GeneralSubtree[]? ParseSubtrees(string? json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            var entries = JsonSerializer.Deserialize<List<string>>(json, SafeJsonOptions.Default);
            if (entries == null || entries.Count == 0) return null;

            return entries.Select(entry =>
            {
                var colonIdx = entry.IndexOf(':');
                if (colonIdx < 0) return null;
                var prefix = entry[..colonIdx].Trim().ToUpperInvariant();
                var value = entry[(colonIdx + 1)..].Trim();

                GeneralName? gn = prefix switch
                {
                    "DNS" => new GeneralName(GeneralName.DnsName, value),
                    "IP" => new GeneralName(GeneralName.IPAddress, value),
                    "EMAIL" => new GeneralName(GeneralName.Rfc822Name, value),
                    "URI" => new GeneralName(GeneralName.UniformResourceIdentifier, value),
                    // DirectoryName subtrees are parsed through the DN
                    // sanitizer before handing them to X509Name so a malicious profile
                    // can't smuggle control chars / BIDI overrides into a permitted /
                    // excluded DN subtree.
                    "DN" => new GeneralName(
                        GeneralName.DirectoryName,
                        new X509Name(SanitizeDnString(value))),
                    _ => null
                };
                return gn != null ? new GeneralSubtree(gn) : null;
            }).Where(s => s != null).ToArray()!;
        }

        /// <summary>
        /// Applies <see cref="DnComponentSanitizer"/> to every RDN component of a
        /// comma-separated DN string, rebuilding it in canonical form. Used by
        /// <see cref="ParseSubtrees"/> so NameConstraints subtrees can't carry
        /// invisible / spoofing characters into a cert.
        /// </summary>
        private static string SanitizeDnString(string dn)
        {
            // Cheap pre-parser: split on commas that are not escaped. X509Name
            // re-parses the result so we keep the same canonicalisation
            // semantics for the final construct; we're just rejecting malicious
            // characters up front.
            var parts = dn.Split(',');
            var rebuilt = new List<string>(parts.Length);
            foreach (var raw in parts)
            {
                var eq = raw.IndexOf('=');
                if (eq <= 0)
                {
                    throw new InvalidOperationException($"DN component '{raw}' is missing a '='.");
                }
                var field = raw[..eq].Trim();
                var value = raw[(eq + 1)..];
                var sanitized = DnComponentSanitizer.Sanitize(field, value, DnComponentSanitizer.GetMaxLength(field));
                rebuilt.Add($"{field}={sanitized}");
            }
            return string.Join(",", rebuilt);
        }

        /// <summary>
        /// Derives the matching <see cref="AsymmetricKeyParameter"/> public key for
        /// a software-backed private key, supporting RSA, ECDSA, Ed25519/Ed448,
        /// ML-DSA and SLH-DSA. Returns <c>null</c> for unknown key types — the
        /// AKI assert treats that as "unable to verify, trust the caller".
        /// </summary>
        private static AsymmetricKeyParameter? DerivePublicKey(AsymmetricKeyParameter priv)
        {
            if (!priv.IsPrivate) return null;
            return priv switch
            {
                Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters rsa =>
                    new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
                Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters ec =>
                    new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(
                        ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D), ec.Parameters),
                Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters ed25519 =>
                    ed25519.GeneratePublicKey(),
                Org.BouncyCastle.Crypto.Parameters.Ed448PrivateKeyParameters ed448 =>
                    ed448.GeneratePublicKey(),
                _ => null
            };
        }
    }
}
