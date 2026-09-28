using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using ModularCA.Shared.Entities;

namespace ModularCA.Database.Conventions;

/// <summary>
/// Decides, for every text column that participates in a unique index, whether two values that
/// differ only in case are the same value.
/// <para>
/// MySQL answered this once for the whole database: its default collation is case-insensitive, so
/// <c>Admin</c> and <c>admin</c> were one username, one CA label, one hostname. PostgreSQL's
/// default collation is case-sensitive, so the same schema silently answers the opposite way, and
/// the failures it produces are quiet ones: a user who cannot sign in with the capitalisation they
/// have always used, a second CA protocol configuration row that shadows the first, a CRL issued
/// twice under one number because two spellings of an issuer name are two issuers.
/// </para>
/// <para>
/// So the answer is written down per column instead of inherited from a server default. Columns in
/// <see cref="CaseInsensitive"/> are declared <c>citext</c>, which folds case inside the type:
/// equality, <c>LIKE</c> and the unique index all behave as they did on MySQL, and no query has to
/// remember to lower its argument. That last property is the reason for choosing it over a unique
/// index on <c>lower(col)</c> — an expression index only helps the queries written to use it, and
/// a lookup that forgets is case-sensitive again with nothing to show for it.
/// </para>
/// <para>
/// Columns in <see cref="CaseSensitiveByDesign"/> stay ordinary text, each with its reason recorded
/// beside it. Most are base64 or base64url, where folding case is not a nicety but a defect: it
/// halves the alphabet of a bearer token, a replay nonce or an account thumbprint. MySQL folded
/// them, and the move to PostgreSQL fixes that rather than breaking anything.
/// </para>
/// <para>
/// Nothing may be absent from both sets. <c>TextCaseSensitivityTests</c> walks the built model and
/// fails the build when a unique index covers a text column no one has classified, so a new index
/// cannot inherit an answer by accident the way the whole schema used to.
/// </para>
/// </summary>
public static class TextCaseSensitivity
{
    /// <summary>A text column, identified by its entity type and property name.</summary>
    /// <param name="Entity">The CLR entity type the property belongs to.</param>
    /// <param name="Property">The property name, as declared on the entity.</param>
    public readonly record struct Column(Type Entity, string Property)
    {
        /// <summary>Renders the column as <c>EntityName.PropertyName</c> for failure messages.</summary>
        public override string ToString() => $"{Entity.Name}.{Property}";
    }

    /// <summary>
    /// The PostgreSQL extension providing <c>citext</c>. It ships in <c>postgresql-contrib</c> and
    /// is available on every managed PostgreSQL service we have checked.
    /// </summary>
    public const string Extension = "citext";

    /// <summary>The column type applied to every <see cref="CaseInsensitive"/> column.</summary>
    public const string CaseInsensitiveColumnType = "citext";

    /// <summary>
    /// Columns where two spellings differing only in case name the same thing, and the database
    /// must agree.
    /// </summary>
    public static IReadOnlySet<Column> CaseInsensitive { get; } = new HashSet<Column>
    {
        // Sign-in. The one that locks people out of their own installation.
        new(typeof(UserEntity), nameof(UserEntity.Username)),
        new(typeof(UserEntity), nameof(UserEntity.Email)),

        // Names that appear in a URL, where the browser, the operator and the client each supply
        // their own capitalisation: the tenant slug in a path and the CA label in /scep/{label}
        // and /acme/{label}.
        new(typeof(TenantEntity), nameof(TenantEntity.Slug)),
        new(typeof(CertificateAuthorityEntity), nameof(CertificateAuthorityEntity.Label)),

        // Authorization subjects. Two roles or two groups differing only in case would each carry
        // half of somebody's rights.
        new(typeof(RoleEntity), nameof(RoleEntity.Name)),
        new(typeof(CaGroupEntity), nameof(CaGroupEntity.Name)),
        new(typeof(AccessBadgeEntity), nameof(AccessBadgeEntity.Name)),

        // Kerberos realms are conventionally uppercase and compared without regard to case; a
        // client that sends the realm in whatever case its resolver handed it must still match.
        // The enctype beside it is a protocol constant read out of a keytab, and one realm must
        // not end up holding two keys for one kvno because two tools spelled AES256 differently.
        new(typeof(KerberosRealmEntity), nameof(KerberosRealmEntity.Realm)),
        new(typeof(KerberosRealmKeyEntity), nameof(KerberosRealmKeyEntity.EncryptionType)),

        // Operator-facing names. Uniqueness here is what stops two profiles a human would read as
        // the same name from existing side by side.
        new(typeof(TenantEntity), nameof(TenantEntity.Name)),
        new(typeof(CertificateAuthorityEntity), nameof(CertificateAuthorityEntity.Name)),
        new(typeof(CertProfileEntity), nameof(CertProfileEntity.Name)),
        new(typeof(SigningProfileEntity), nameof(SigningProfileEntity.Name)),
        new(typeof(RequestProfileEntity), nameof(RequestProfileEntity.Name)),
        new(typeof(CertificateTemplateEntity), nameof(CertificateTemplateEntity.Name)),
        new(typeof(SshSigningProfileEntity), nameof(SshSigningProfileEntity.Name)),
        new(typeof(SshCertProfileEntity), nameof(SshCertProfileEntity.Name)),
        new(typeof(SshRequestProfileEntity), nameof(SshRequestProfileEntity.Name)),
        new(typeof(SshCertificateTemplateEntity), nameof(SshCertificateTemplateEntity.Name)),
        new(typeof(CrlConfigurationEntity), nameof(CrlConfigurationEntity.Name)),
        new(typeof(LdapConfigurationEntity), nameof(LdapConfigurationEntity.Name)),
        new(typeof(KeystoreEntryEntity), nameof(KeystoreEntryEntity.Name)),
        new(typeof(FeatureFlagEntity), nameof(FeatureFlagEntity.Name)),

        // Distinguished names and hex. RFC 4518 compares the string attribute types in a DN
        // without regard to case, and a hex serial is the same number whichever case renders it.
        // Both carry a consequence past tidiness: (SerialNumber, Issuer) is what stops one
        // certificate being imported twice, and (IssuerName, CrlNumber) is what stops one issuer
        // publishing two different CRLs under a single number.
        new(typeof(CertificateEntity), nameof(CertificateEntity.SerialNumber)),
        new(typeof(CertificateEntity), nameof(CertificateEntity.Issuer)),
        new(typeof(TrustAnchorEntity), nameof(TrustAnchorEntity.SerialNumber)),
        new(typeof(TrustAnchorEntity), nameof(TrustAnchorEntity.Issuer)),
        new(typeof(CrlEntity), nameof(CrlEntity.IssuerName)),

        // Protocol names held as text. A second row spelled "acme" would be a complete, editable
        // protocol configuration that nothing ever reads.
        new(typeof(CaProtocolConfigEntity), nameof(CaProtocolConfigEntity.Protocol)),
        new(typeof(WhitelistEntity), nameof(WhitelistEntity.Protocol)),

        // Replay keys. Folding case can only ever reject more replays, never fewer, so the
        // direction of being wrong here is the safe one, which is the argument for keeping the
        // behaviour MySQL had rather than tightening it in passing.
        new(typeof(ScepTransactionEntity), nameof(ScepTransactionEntity.TransactionId)),
        new(typeof(CmpTransactionEntity), nameof(CmpTransactionEntity.TransactionId)),

        // Scheduler identity, and both of these are text primary keys rather than indexes. The
        // names come from compile-time constants, so a mismatch should be impossible — but the
        // lease is what stops two nodes running one job at once, and if two spellings of a job
        // name were ever two leases, both nodes would hold one and believe they had it alone.
        // Folding case costs nothing and removes that as a possible outcome.
        new(typeof(SchedulerLeaseEntity), nameof(SchedulerLeaseEntity.Name)),
        new(typeof(SchedulerJobStateEntity), nameof(SchedulerJobStateEntity.JobName)),

        // Deduplication keys for notifications, preferences and tags: written by one part of the
        // product and read by another, none of them secret.
        new(typeof(NotificationLogEntity), nameof(NotificationLogEntity.EventType)),
        new(typeof(NotificationLogEntity), nameof(NotificationLogEntity.TargetEntityId)),
        new(typeof(UserPreferenceEntity), nameof(UserPreferenceEntity.Key)),
        new(typeof(CertificateTagEntity), nameof(CertificateTagEntity.Key)),
    };

    /// <summary>
    /// Columns that stay case-sensitive, each with the reason. Every entry is a place where the
    /// folding MySQL did was a defect rather than a feature, or where no case can occur at all.
    /// </summary>
    public static IReadOnlyDictionary<Column, string> CaseSensitiveByDesign { get; } =
        new Dictionary<Column, string>
        {
            [new(typeof(RefreshTokenEntity), nameof(RefreshTokenEntity.Token))] =
                "A bearer secret. Comparing it without regard to case collapses the alphabet the "
                + "token was drawn from, which is a straight reduction in the work needed to "
                + "guess one. MySQL did exactly that.",

            [new(typeof(EnrollmentTokenEntity), nameof(EnrollmentTokenEntity.Token))] =
                "A SHA-256 of the enrollment token, in hex we render ourselves, so only one "
                + "casing is ever stored and folding would buy nothing. It is looked up as a "
                + "credential, and a credential is compared exactly.",

            [new(typeof(AcmeAccountEntity), nameof(AcmeAccountEntity.JwkThumbprint))] =
                "Base64url of a key thumbprint. Case is significant in base64url, so folding it "
                + "invents collisions between accounts holding genuinely different keys.",

            [new(typeof(AcmeNonceEntity), nameof(AcmeNonceEntity.Value))] =
                "Base64url replay nonce. Case is significant, and the entire value of a nonce is "
                + "that it is the one that was issued.",

            [new(typeof(AcmeEabKeyEntity), nameof(AcmeEabKeyEntity.KeyId))] =
                "The ACME external-account key identifier. RFC 8555 treats it as an opaque "
                + "string, and it names the MAC key a client is about to prove possession of.",

            [new(typeof(Fido2CredentialEntity), nameof(Fido2CredentialEntity.CredentialId))] =
                "Base64url credential identifier minted by an authenticator, compared against "
                + "what the browser hands back verbatim.",

            [new(typeof(TotpRecoveryCodeEntity), nameof(TotpRecoveryCodeEntity.CodeHash))] =
                "A hash standing in for a single-use credential. Compared exactly.",

            [new(typeof(OIDOptionEntity), nameof(OIDOptionEntity.OID))] =
                "An object identifier: digits and dots, so there is no case to be sensitive to.",

            [new(typeof(CertificateTemplateEntity), nameof(CertificateTemplateEntity.MsaeTemplateOid))] =
                "An object identifier: digits and dots, so there is no case to be sensitive to.",
        };

    /// <summary>
    /// Declares the <c>citext</c> extension and applies the case-insensitive column type to every
    /// column in <see cref="CaseInsensitive"/>.
    /// <para>
    /// <c>citext</c> takes no length modifier, so a column that carried
    /// <c>character varying(n)</c> would quietly lose its length limit on the way across. Each
    /// converted column therefore gains an explicit <c>length(col) &lt;= n</c> check constraint
    /// carrying the same maximum length the model already declares, so the limit stays enforced by
    /// the database rather than only by the annotation.
    /// </para>
    /// </summary>
    /// <param name="modelBuilder">The model builder, after every entity has been configured.</param>
    /// <exception cref="InvalidOperationException">A registered column is not a mapped string.</exception>
    public static void Apply(ModelBuilder modelBuilder)
    {
        modelBuilder.HasPostgresExtension(Extension);

        foreach (var column in CaseInsensitive)
        {
            var entityType = modelBuilder.Model.FindEntityType(column.Entity)
                ?? throw new InvalidOperationException(
                    $"{column.Entity.Name} is registered in TextCaseSensitivity but is not in the model.");

            var property = entityType.FindProperty(column.Property)
                ?? throw new InvalidOperationException(
                    $"{column} is registered in TextCaseSensitivity but is not a mapped property.");

            if (property.ClrType != typeof(string))
                throw new InvalidOperationException(
                    $"{column} is registered in TextCaseSensitivity but is {property.ClrType.Name}, not a string.");

            property.SetColumnType(CaseInsensitiveColumnType);

            var table = entityType.GetTableName();
            if (table is null || property.GetMaxLength() is not int maxLength)
                continue;

            var columnName = property.GetColumnName();
            modelBuilder.Entity(column.Entity).ToTable(t => t.HasCheckConstraint(
                $"CK_{table}_{columnName}_Length",
                $"length(\"{columnName}\") <= {maxLength}"));
        }
    }

    /// <summary>
    /// Returns every text column under a uniqueness constraint that appears in neither set: the
    /// columns whose case behaviour would otherwise be decided by whatever collation the server
    /// happened to be created with.
    /// <para>
    /// Unique indexes are the obvious source, but a primary or alternate key over a text column
    /// asks exactly the same question and is declared through a different API, so all three are
    /// walked. <c>SchedulerLeases</c> is keyed by its name and has no index at all; it would have
    /// been missed entirely by a sweep that only read <see cref="IReadOnlyEntityType.GetIndexes"/>.
    /// </para>
    /// </summary>
    /// <param name="model">A built model.</param>
    /// <returns>The unclassified columns; empty when every one has been decided.</returns>
    public static IEnumerable<Column> Unclassified(IModel model)
    {
        foreach (var entityType in model.GetEntityTypes())
        {
            var constrained = entityType.GetIndexes().Where(i => i.IsUnique).Select(i => i.Properties)
                .Concat(entityType.GetKeys().Select(k => k.Properties));

            foreach (var properties in constrained)
            {
                foreach (var property in properties.Where(p => p.ClrType == typeof(string)))
                {
                    var column = new Column(entityType.ClrType, property.Name);
                    if (CaseInsensitive.Contains(column) || CaseSensitiveByDesign.ContainsKey(column))
                        continue;
                    yield return column;
                }
            }
        }
    }
}
