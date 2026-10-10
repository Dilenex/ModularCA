using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Models;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A certificate request is held to the request profile it was made under when it is submitted
/// through the console, when it is approved and when it is issued, with the names the certificate
/// would carry. The rules are read as bootstrap stores them, and a protocol's request carries
/// into its certificate what the profile settled.
/// </summary>
public sealed class RequestProfileEnforcementTests
{
    /// <summary>The SAN rules of a profile as bootstrap writes them: camel-case keys.</summary>
    private static string SeededSanRules(string[] allowedTypes, bool required, int maxCount = 5)
        => JsonSerializer.Serialize(new
        {
            allowedTypes,
            required,
            rules = allowedTypes.ToDictionary(t => t, _ => (object)new { regex = (string?)null, maxCount }),
        });

    private static string Rules(params SubjectDnFieldRule[] rules) => JsonSerializer.Serialize(rules);

    private static EffectiveRequestProfile Effective(string subjectRules, string? sanRules = null) => new()
    {
        Name = "Servers",
        SubjectDnRules = subjectRules,
        SanRules = sanRules ?? SeededSanRules(["DNS", "IP"], required: false),
    };

    private static List<KeyValuePair<string, string>> Fields(params (string Field, string Value)[] fields)
        => fields.Select(f => new KeyValuePair<string, string>(f.Field, f.Value)).ToList();

    private static string CsrPem(string subject, params GeneralName[] sans)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        DerSet? attributes = null;
        if (sans.Length > 0)
        {
            var extensions = new X509ExtensionsGenerator();
            extensions.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sans));
            attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions.Generate())));
        }
        var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()),
            new X509Name(subject), keys.Public, attributes);
        using var sw = new StringWriter();
        new PemWriter(sw).WriteObject(csr);
        return sw.ToString();
    }

    private static RequestProfileEnforcement Enforcement(ModularCADbContext db)
        => new(db, new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance));

    // ---- reading the rules -----------------------------------------------------------------

    /// <summary>
    /// Bootstrap writes SAN rules with camel-case keys. Read case-sensitively they bound to
    /// nothing, so every seeded profile allowed DNS and IP, required no SAN and had no per-type rule.
    /// </summary>
    [Fact]
    public void Seeded_san_rules_are_read_as_written()
    {
        var seeded = SeededSanRules(["Email"], required: true, maxCount: 2);
        var asItWasRead = JsonSerializer.Deserialize<SanRules>(seeded)!;
        Assert.Equal(["DNS", "IP"], asItWasRead.AllowedTypes);
        Assert.False(asItWasRead.Required);

        var rules = RequestProfileValidationService.ReadSanRules(seeded)!;
        Assert.Equal(["Email"], rules.AllowedTypes);
        Assert.True(rules.Required);
        Assert.Equal(2, rules.Rules["Email"].MaxCount);

        var consoleWritten = RequestProfileValidationService.ReadSanRules(JsonSerializer.Serialize(new SanRules { AllowedTypes = ["URI"], Required = true }))!;
        Assert.Equal(["URI"], consoleWritten.AllowedTypes);
        Assert.True(consoleWritten.Required);

        Assert.Equal(["DNS", "IP"], RequestProfileValidationService.ReadSanRules("{}")!.AllowedTypes);
        Assert.Equal(["DNS", "IP"], RequestProfileValidationService.ReadSanRules(null)!.AllowedTypes);
    }

    [Fact]
    public void A_profile_that_lists_no_san_type_allows_none()
    {
        var none = RequestProfileValidationService.ReadSanRules(SeededSanRules([], required: false))!;
        Assert.Contains("allows no subject alternative names", RequestProfileValidationService.ValidateSans(["DNS:a.example"], none));
        Assert.Null(RequestProfileValidationService.ValidateSans([], none));

        var mail = RequestProfileValidationService.ReadSanRules(SeededSanRules(["Email"], required: false))!;
        Assert.Null(RequestProfileValidationService.ValidateSans(["EMAIL:a@example.test", "rfc822:b@example.test"], mail));
        Assert.Contains("SAN type 'DNS' is not allowed", RequestProfileValidationService.ValidateSans(["DNS:a.example"], mail));
        Assert.Contains("Too many SANs", RequestProfileValidationService.ValidateSans(
            ["Email:1@x.test", "Email:2@x.test", "Email:3@x.test", "Email:4@x.test", "Email:5@x.test", "Email:6@x.test"], mail));
    }

    /// <summary>The protocols' own check: a seeded profile's required SAN and allowed types hold, and "[]" is no SAN.</summary>
    [Fact]
    public async Task The_protocol_check_enforces_seeded_san_rules()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = new RequestProfileEntity
        {
            Name = "Enterprise Server (EST)",
            SubjectDnRules = Rules(new SubjectDnFieldRule { Field = "CN", Requirement = "Required" }),
            SanRules = SeededSanRules(["DNS", "IP"], required: true),
        };
        db.RequestProfiles.Add(profile);
        await db.SaveChangesAsync();
        var validation = new RequestProfileValidationService(db, new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance));

        Assert.True((await validation.ValidateAsync(profile.Id, "CN=host", "[\"DNS:host.example\"]")).IsValid);
        foreach (var noSan in new[] { "[]", null, "" })
        {
            var refused = await validation.ValidateAsync(profile.Id, "CN=host", noSan);
            Assert.False(refused.IsValid);
            Assert.Contains("At least one Subject Alternative Name is required", refused.Error);
        }
        var wrongType = await validation.ValidateAsync(profile.Id, "CN=host", "[\"EMAIL:a@example.test\"]");
        Assert.False(wrongType.IsValid);
        Assert.Contains("SAN type 'EMAIL' is not allowed", wrongType.Error);
    }

    // ---- the rule set ----------------------------------------------------------------------

    [Fact]
    public void Names_are_checked_without_being_rewritten()
    {
        var profile = Effective(Rules(
            new SubjectDnFieldRule { Field = "CN", Requirement = "Required", Regex = "^[a-z0-9.-]+$", MaxLength = 20 },
            new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" },
            new SubjectDnFieldRule { Field = "OU", Requirement = "forbidden" },
            new SubjectDnFieldRule { Field = "C", Requirement = "Required", DefaultValue = "US" }),
            SeededSanRules(["DNS"], required: true));
        string? Why((string, string)[] subject, params string[] sans) => RequestProfileEnforcement.WhyNamesRefused(profile, Fields(subject), sans);

        Assert.Null(Why([("CN", "host.example"), ("O", "Acme"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("'CN' is required", Why([("O", "Acme"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("does not match the pattern", Why([("CN", "Host Example"), ("O", "Acme"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("longer than 20", Why([("CN", "a-very-long-host-name.example"), ("O", "Acme"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("'O' must be 'Acme'", Why([("CN", "host.example"), ("O", "Evil"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("'O' must be 'Acme'", Why([("CN", "host.example"), ("C", "US")], "DNS:host.example"));
        Assert.Contains("'OU' is not allowed", Why([("CN", "host.example"), ("O", "Acme"), ("OU", "x"), ("C", "US")], "DNS:host.example"));
        // A default is not assumed here: the field must be present by the time the names are final.
        Assert.Contains("'C' is required", Why([("CN", "host.example"), ("O", "Acme")], "DNS:host.example"));
        Assert.Contains("at least one subject alternative name is required", Why([("CN", "host.example"), ("O", "Acme"), ("C", "US")]));
        Assert.Contains("SAN type 'IP' is not allowed", Why([("CN", "host.example"), ("O", "Acme"), ("C", "US")], "IP:10.0.0.1"));
    }

    [Fact]
    public void Every_value_of_a_repeated_field_is_checked_and_field_names_are_matched_in_any_spelling()
    {
        var profile = Effective(Rules(
            new SubjectDnFieldRule { Field = "OU", Requirement = "Optional", Regex = "^[A-Z]+$" },
            new SubjectDnFieldRule { Field = "E", Requirement = "Forbidden" }));

        Assert.Null(RequestProfileEnforcement.WhyNamesRefused(profile, Fields(("CN", "x"), ("ou", "OPS"), ("OU", "DEV")), []));
        Assert.Contains("'OU' value 'dev'", RequestProfileEnforcement.WhyNamesRefused(profile, Fields(("OU", "OPS"), ("OU", "dev")), []));
        Assert.Contains("'E' is not allowed", RequestProfileEnforcement.WhyNamesRefused(profile, Fields(("emailAddress", "a@x.test")), []));

        var subject = RequestProfileEnforcement.FieldsOf(new X509Name("CN=x,OU=OPS,OU=dev,E=a@x.test,C=US"));
        Assert.Equal(["CN", "OU", "OU", "E", "C"], subject.Select(f => f.Key));
        Assert.Contains("'OU' value 'dev'", RequestProfileEnforcement.WhyNamesRefused(profile, subject, []));
    }

    [Fact]
    public void The_profile_supplies_what_it_fixes_and_what_it_defaults()
    {
        var profile = Effective(Rules(
            new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" },
            new SubjectDnFieldRule { Field = "C", Requirement = "Required", DefaultValue = "US" },
            new SubjectDnFieldRule { Field = "L", Requirement = "Optional", DefaultValue = "Reno" }));

        var (settled, supplied) = RequestProfileEnforcement.Settle(profile, Fields(("CN", "x"), ("O", "Evil"), ("L", "Austin")));
        Assert.Equal(new Dictionary<string, string> { ["O"] = "Acme", ["C"] = "US" }, supplied);
        Assert.Equal([("CN", "x"), ("L", "Austin"), ("O", "Acme"), ("C", "US")], settled.Select(f => (f.Key, f.Value)));
        Assert.Null(RequestProfileEnforcement.WhyNamesRefused(profile, settled, []));

        var (_, nothing) = RequestProfileEnforcement.Settle(profile, Fields(("CN", "x"), ("O", "Acme"), ("C", "DE"), ("L", "Bonn")));
        Assert.Empty(nothing);
    }

    // ---- submission ------------------------------------------------------------------------

    [Fact]
    public async Task A_submission_names_a_certificate_profile_its_request_profile_allows()
    {
        using var db = InMemoryDbContextFactory.Create();
        var tls = new CertProfileEntity { Name = "TLS Server" };
        var other = new CertProfileEntity { Name = "Other" };
        var open = new RequestProfileEntity { Name = "Open", SanRules = "{}" };
        var pinned = new RequestProfileEntity { Name = "Pinned", SanRules = "{}", DefaultCertProfileId = tls.Id };
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        db.AddRange(tls, other, open, pinned, signing);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);
        Task<Dictionary<string, string>> Submit(Guid requestProfile, Guid certProfile, bool selfService)
            => enforcement.SettleSubmissionAsync(requestProfile, certProfile, signing.Id, selfService, Fields(("CN", "x")), []);

        Assert.Empty(await Submit(pinned.Id, tls.Id, selfService: true));
        Assert.Empty(await Submit(pinned.Id, tls.Id, selfService: false));
        foreach (var selfService in new[] { true, false })
        {
            var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(() => Submit(pinned.Id, other.Id, selfService));
            Assert.Equal(ErrorCodes.RequestProfileRefused, refused.Code);
            Assert.Contains("'Pinned'", refused.Message);
            Assert.Contains("Allowed: TLS Server", refused.Message);
        }

        // A request profile that names no certificate profile: any for an operator, none for a requester.
        Assert.Empty(await Submit(open.Id, other.Id, selfService: false));
        Assert.Contains("names no certificate profile",
            (await Assert.ThrowsAsync<ConfigurationValidationException>(() => Submit(open.Id, other.Id, selfService: true))).Message);

        Assert.Contains("does not exist",
            (await Assert.ThrowsAsync<ConfigurationValidationException>(() => Submit(Guid.NewGuid(), tls.Id, selfService: false))).Message);
    }

    [Fact]
    public async Task A_request_profile_bound_to_a_ca_serves_that_ca_only()
    {
        using var db = InMemoryDbContextFactory.Create();
        var mine = new CertificateAuthorityEntity { Name = "Mine", Label = "mine", CertificateId = Guid.NewGuid() };
        var theirs = new CertificateAuthorityEntity { Name = "Theirs", Label = "theirs", CertificateId = Guid.NewGuid() };
        var mySigning = new SigningProfileEntity { Name = "mine", AllowedAlgorithms = "[]", IssuerId = mine.CertificateId };
        var theirSigning = new SigningProfileEntity { Name = "theirs", AllowedAlgorithms = "[]", IssuerId = theirs.CertificateId };
        var cert = new CertProfileEntity { Name = "Any" };
        var bound = new RequestProfileEntity { Name = "Bound", SanRules = "{}", CertificateAuthorityId = mine.Id };
        db.AddRange(mine, theirs, mySigning, theirSigning, cert, bound);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);

        Assert.Empty(await enforcement.SettleSubmissionAsync(bound.Id, cert.Id, mySigning.Id, false, Fields(("CN", "x")), []));
        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => enforcement.SettleSubmissionAsync(bound.Id, cert.Id, theirSigning.Id, false, Fields(("CN", "x")), []));
        Assert.Contains("another CA", refused.Message);
    }

    [Fact]
    public async Task A_key_request_gets_the_profiles_values_and_is_refused_on_its_names()
    {
        using var db = InMemoryDbContextFactory.Create();
        var cert = new CertProfileEntity { Name = "TLS Server" };
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        var profile = new RequestProfileEntity
        {
            Name = "Servers",
            DefaultCertProfileId = cert.Id,
            SubjectDnRules = Rules(
                new SubjectDnFieldRule { Field = "CN", Requirement = "Required" },
                new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" }),
            SanRules = SeededSanRules(["DNS"], required: true),
        };
        db.AddRange(cert, signing, profile);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);

        var subject = await enforcement.SettleKeyRequestAsync(profile.Id, cert.Id, signing.Id, true,
            new Dictionary<string, string> { ["CN"] = "host.example", ["o"] = "Evil" }, [new SanOverride { Type = "dns", Value = "host.example" }]);
        Assert.Equal(new Dictionary<string, string> { ["CN"] = "host.example", ["O"] = "Acme" }, subject);

        var noSan = await Assert.ThrowsAsync<ConfigurationValidationException>(() => enforcement.SettleKeyRequestAsync(
            profile.Id, cert.Id, signing.Id, true, new Dictionary<string, string> { ["CN"] = "host.example" }, []));
        Assert.Contains("at least one subject alternative name is required", noSan.Message);
        var wrongType = await Assert.ThrowsAsync<ConfigurationValidationException>(() => enforcement.SettleKeyRequestAsync(
            profile.Id, cert.Id, signing.Id, true, new Dictionary<string, string> { ["CN"] = "host.example" }, [new SanOverride { Type = "Email", Value = "a@x.test" }]));
        Assert.Contains("SAN type 'EMAIL' is not allowed", wrongType.Message);

        Assert.Equal("CN=host.example,O=Acme", await enforcement.SettleSubjectNameAsync(
            profile.Id, cert.Id, signing.Id, false, "CN=host.example", ["DNS:host.example"]));
    }

    [Fact]
    public async Task An_uploaded_csr_is_checked_with_its_overrides_applied()
    {
        using var db = InMemoryDbContextFactory.Create();
        var cert = new CertProfileEntity { Name = "TLS Server" };
        var signing = new SigningProfileEntity { Name = "signing", AllowedAlgorithms = "[]" };
        var profile = new RequestProfileEntity
        {
            Name = "Servers",
            DefaultCertProfileId = cert.Id,
            SubjectDnRules = Rules(
                new SubjectDnFieldRule { Field = "CN", Requirement = "Required", Regex = "^[a-z.]+$" },
                new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" },
                new SubjectDnFieldRule { Field = "OU", Requirement = "Forbidden" }),
            SanRules = SeededSanRules(["DNS"], required: true),
        };
        db.AddRange(cert, signing, profile);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);
        var csr = CsrPem("CN=host.example,O=Evil", new GeneralName(GeneralName.DnsName, "host.example"));
        Task<Dictionary<string, string>?> Upload(string pem, Dictionary<string, string>? subject = null, List<SanOverride>? sans = null)
            => enforcement.SettleUploadAsync(profile.Id, cert.Id, signing.Id, true, pem, subject, sans);

        // The profile's own value is added to the overrides, and the caller's are kept.
        Assert.Equal(new Dictionary<string, string> { ["O"] = "Acme" }, await Upload(csr));
        Assert.Equal(new Dictionary<string, string> { ["CN"] = "other.example", ["O"] = "Acme" },
            await Upload(csr, new Dictionary<string, string> { ["CN"] = "other.example", ["o"] = "Evil" }));

        // An override is part of the names: one that breaks a rule is refused, and one that mends it passes.
        Assert.Contains("'CN' value 'Other Example'", (await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Upload(csr, new Dictionary<string, string> { ["CN"] = "Other Example" }))).Message);
        Assert.Contains("SAN type 'EMAIL' is not allowed", (await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Upload(csr, null, [new SanOverride { Type = "Email", Value = "a@x.test" }]))).Message);
        var noSanCsr = CsrPem("CN=host.example");
        await Assert.ThrowsAsync<ConfigurationValidationException>(() => Upload(noSanCsr));
        Assert.NotNull(await Upload(noSanCsr, null, [new SanOverride { Type = "DNS", Value = "host.example" }]));

        // What cannot be removed by an override is refused: the CSR itself carries the forbidden field.
        Assert.Contains("'OU' is not allowed", (await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Upload(CsrPem("CN=host.example,OU=x", new GeneralName(GeneralName.DnsName, "host.example"))))).Message);

        // A CSR that cannot be read is left to the upload, which refuses it.
        var asGiven = new Dictionary<string, string> { ["CN"] = "x" };
        Assert.Same(asGiven, await Upload("not a csr", asGiven));
    }

    // ---- protocols -------------------------------------------------------------------------

    [Fact]
    public void A_protocol_request_carries_what_the_profile_settled_into_its_certificate()
    {
        var profile = Effective(Rules(
            new SubjectDnFieldRule { Field = "CN", Requirement = "Required" },
            new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" },
            new SubjectDnFieldRule { Field = "C", Requirement = "Optional", DefaultValue = "US" }));

        var overrides = RequestProfileEnforcement.ProtocolSubjectOverrides(profile, CsrPem("CN=host,O=Evil"), "[]", "CN=host,O=Acme,C=US");
        Assert.Equal(new Dictionary<string, string> { ["O"] = "Acme", ["C"] = "US" }, JsonSerializer.Deserialize<Dictionary<string, string>>(overrides!));

        // Nothing to add when the CSR already says what the profile settled.
        Assert.Null(RequestProfileEnforcement.ProtocolSubjectOverrides(profile, CsrPem("CN=host,O=Acme,C=DE"), "[]", "CN=host,O=Acme,C=DE"));

        var plain = Effective(Rules(new SubjectDnFieldRule { Field = "CN", Requirement = "Required" }));
        // An empty CSR subject takes its common name from the first DNS SAN at issuance already.
        Assert.Null(RequestProfileEnforcement.ProtocolSubjectOverrides(plain, CsrPem(""), "[\"DNS:host.example\"]", "CN=host.example"));
        // A subject with no common name and no DNS SAN to take one from gets the one the protocol settled.
        Assert.Equal("{\"CN\":\"10.0.0.1\"}", RequestProfileEnforcement.ProtocolSubjectOverrides(plain, CsrPem("O=Acme"), "[\"IP:10.0.0.1\"]", "CN=10.0.0.1,O=Acme"));

        Assert.Null(RequestProfileEnforcement.ProtocolSubjectOverrides(profile, "-----CMP-PUBKEY-----\nAAAA\n", "[]", "CN=host,O=Acme"));
        Assert.Null(RequestProfileEnforcement.ProtocolSubjectOverrides(profile, null, "[]", "CN=host"));
    }

    // ---- approval and issuance -------------------------------------------------------------

    [Fact]
    public async Task A_stored_request_is_judged_by_its_profile_as_the_profile_is_now()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = new RequestProfileEntity
        {
            Name = "Servers",
            SubjectDnRules = Rules(new SubjectDnFieldRule { Field = "CN", Requirement = "Required" }),
            SanRules = SeededSanRules(["DNS"], required: false),
        };
        db.RequestProfiles.Add(profile);
        await db.SaveChangesAsync();
        var enforcement = Enforcement(db);
        var request = new CertRequestEntity
        {
            CSR = CsrPem("CN=host.example,O=Evil"),
            Subject = "CN=host.example,O=Evil",
            SubjectAlternativeNames = "[\"DNS:host.example\"]",
            RequestProfileId = profile.Id,
        };

        Assert.Null(await enforcement.WhyRefusedAsync(request));

        profile.SubjectDnRules = Rules(
            new SubjectDnFieldRule { Field = "CN", Requirement = "Required" },
            new SubjectDnFieldRule { Field = "O", Requirement = "Forbidden" });
        await db.SaveChangesAsync();
        var why = await enforcement.WhyRefusedAsync(request);
        Assert.Contains("The request profile 'Servers' does not permit this request", why);
        Assert.Contains("'O' is not allowed", why);

        // Overrides are part of the names an approver agrees to.
        request.CSR = CsrPem("CN=host.example");
        request.SanOverrides = "[\"EMAIL:a@x.test\"]";
        Assert.Contains("SAN type 'EMAIL' is not allowed", await enforcement.WhyRefusedAsync(request));
        request.SanOverrides = null;
        Assert.Null(await enforcement.WhyRefusedAsync(request));

        // A CMP request holds no CSR: its recorded subject is read.
        var cmp = new CertRequestEntity { CSR = "-----CMP-PUBKEY-----\nAAAA\n", Subject = "CN=device,O=Evil", SubjectAlternativeNames = "[]", RequestProfileId = profile.Id };
        Assert.Contains("'O' is not allowed", await enforcement.WhyRefusedAsync(cmp));

        // A request made under no profile, and one whose profile is gone.
        Assert.Null(await enforcement.WhyRefusedAsync(new CertRequestEntity { CSR = request.CSR, Subject = "CN=x,O=Evil" }));
        Assert.Contains("no longer exists", await enforcement.WhyRefusedAsync(
            new CertRequestEntity { CSR = request.CSR, Subject = "CN=x", RequestProfileId = Guid.NewGuid() }));
    }

    /// <summary>
    /// Issuance holds the final names to the request profile, so nothing stored on the request
    /// after it was checked (an override, a changed profile) reaches a certificate unchecked.
    /// </summary>
    [Fact]
    public async Task Issuance_refuses_final_names_the_request_profile_does_not_permit()
    {
        var w = new NameConstraintIssuanceTests.IssuanceWorld();
        var ca = await w.CreateRootAsync("Profile Root", null, null);
        var profile = new RequestProfileEntity
        {
            Name = "Servers",
            SubjectDnRules = Rules(
                new SubjectDnFieldRule { Field = "CN", Requirement = "Required" },
                new SubjectDnFieldRule { Field = "O", Requirement = "Optional", FixedValue = "Acme" }),
            SanRules = SeededSanRules(["DNS"], required: true),
        };
        w.Db.RequestProfiles.Add(profile);
        w.Db.SaveChanges();

        var fixedBroken = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => w.IssueLeafAsync(ca, "CN=leaf,O=Evil", ["DNS:leaf.example"], requestProfileId: profile.Id));
        Assert.Equal(ErrorCodes.RequestProfileRefused, fixedBroken.Code);
        Assert.Contains("'O' must be 'Acme'", fixedBroken.Message);

        var overridden = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => w.IssueLeafAsync(ca, "CN=leaf,O=Acme", ["DNS:leaf.example"], sanOverrides: "[\"EMAIL:a@x.test\"]", requestProfileId: profile.Id));
        Assert.Contains("SAN type 'EMAIL' is not allowed", overridden.Message);

        await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => w.IssueLeafAsync(ca, "CN=leaf,O=Acme", [], requestProfileId: profile.Id));

        // The profile's value, carried as an override, is in the certificate.
        var issued = await w.IssueLeafAsync(ca, "CN=leaf,O=Evil", ["DNS:leaf.example"], requestProfileId: profile.Id, subjectOverrides: "{\"O\":\"Acme\"}");
        var subject = CertificateUtil.ParseFromPem(issued.Pem).SubjectDN.ToString();
        Assert.Contains("O=Acme", subject);
        Assert.DoesNotContain("Evil", subject);

        // A request made under no request profile is issued as before.
        Assert.Contains("BEGIN CERTIFICATE", (await w.IssueLeafAsync(ca, "CN=leaf,O=Evil", ["DNS:leaf.example"])).Pem);
    }

    // ---- deleting a profile ----------------------------------------------------------------

    [Fact]
    public async Task A_request_profile_with_requests_still_waiting_under_it_is_not_deleted()
    {
        using var db = InMemoryDbContextFactory.Create();
        var profile = new RequestProfileEntity { Name = "Servers" };
        var waiting = new CertRequestEntity { CSR = "x", Subject = "CN=a", Status = "Pending", RequestProfileId = profile.Id };
        var done = new CertRequestEntity { CSR = "x", Subject = "CN=b", Status = "Issued", RequestProfileId = profile.Id };
        db.AddRange(profile, waiting, done);
        await db.SaveChangesAsync();
        var service = new RequestProfileService(db);

        var refused = await Assert.ThrowsAsync<ResourceConflictException>(() => service.DeleteAsync(profile.Id));
        Assert.Contains("1 request is still waiting", refused.Message);

        waiting.Status = "Rejected";
        await db.SaveChangesAsync();
        Assert.True(await service.DeleteAsync(profile.Id));
        Assert.Empty(db.RequestProfiles);
    }
}
