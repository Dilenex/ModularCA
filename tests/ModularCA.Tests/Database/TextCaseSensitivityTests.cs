using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using ModularCA.Database;
using ModularCA.Database.Conventions;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Guards the one schema property that changed meaning when the database did.
/// <para>
/// On MySQL the server's collation decided, for the whole database at once, that two values
/// differing only in case were the same value. PostgreSQL decides the opposite, equally globally,
/// and nothing in the model records which answer any given column actually wanted — so the move
/// would have silently changed who can sign in, whether a CA label in a URL resolves, and whether
/// one issuer can publish two CRLs under one number.
/// </para>
/// <para>
/// <see cref="TextCaseSensitivity"/> answers it per column instead. These tests exist so that
/// answer cannot be lost again: a unique index added later over an unclassified text column fails
/// the build rather than quietly inheriting whatever the server was created with.
/// </para>
/// </summary>
public class TextCaseSensitivityTests
{
    // Built against the PostgreSQL provider rather than the in-memory one the rest of the suite
    // uses, because the assertions are about column types and the in-memory provider has none: it
    // answers GetColumnType() with a non-relational type mapping. No connection is opened —
    // building a model is offline work — so this still runs as an ordinary unit test.
    //
    // It is the DESIGN-TIME model, which is the one migrations are generated from. DbContext.Model
    // is a read-optimized projection that keeps only what querying needs, and check constraints
    // and database-level annotations such as the citext extension are not part of that — asking it
    // for them throws rather than returning nothing, which is its way of saying to come here.
    private static readonly IModel PostgresModel = BuildPostgresModel();

    private static IModel BuildPostgresModel()
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseNpgsql("Host=model-build-only;Database=modularca")
            .Options;
        using var db = new ModularCADbContext(options);
        return db.GetService<IDesignTimeModel>().Model;
    }

    private static IModel Model() => PostgresModel;

    // ── The classification is complete ─────────────────────────────────────────

    [Fact]
    public void Every_text_column_under_a_uniqueness_constraint_has_been_classified()
    {
        // The whole point of the exercise. A unique index, primary key or alternate key over a
        // text column is a statement about when two values are the same value, and on PostgreSQL
        // that statement is not complete until someone has said whether case counts. Adding one
        // without deciding is how the original problem happened, so it fails here instead of in
        // production.
        var unclassified = TextCaseSensitivity.Unclassified(Model()).ToList();

        Assert.True(unclassified.Count == 0,
            "These text columns are under a uniqueness constraint but appear in neither "
            + "TextCaseSensitivity.CaseInsensitive nor CaseSensitiveByDesign. Decide whether two "
            + "values differing only in case are the same value, and add each to one set:\n  "
            + string.Join("\n  ", unclassified.Select(c => c.ToString())));
    }

    [Fact]
    public void No_column_is_classified_both_ways()
    {
        var both = TextCaseSensitivity.CaseInsensitive
            .Where(TextCaseSensitivity.CaseSensitiveByDesign.ContainsKey)
            .ToList();

        Assert.True(both.Count == 0, "classified as both: " + string.Join(", ", both));
    }

    [Fact]
    public void Every_case_sensitive_column_carries_a_reason()
    {
        // Case-sensitive is the direction that breaks a lookup that used to work, so it is the
        // direction that has to be argued for. An entry with no reason is an entry nobody thought
        // about.
        foreach (var (column, reason) in TextCaseSensitivity.CaseSensitiveByDesign)
            Assert.False(string.IsNullOrWhiteSpace(reason), $"{column} has no recorded reason");
    }

    // ── The classification reaches the schema ──────────────────────────────────

    [Fact]
    public void Case_insensitive_columns_are_declared_citext()
    {
        var model = Model();

        foreach (var column in TextCaseSensitivity.CaseInsensitive)
        {
            var property = model.FindEntityType(column.Entity)?.FindProperty(column.Property);
            Assert.True(property is not null, $"{column} is registered but not in the model");

            Assert.Equal(TextCaseSensitivity.CaseInsensitiveColumnType, property!.GetColumnType());
        }
    }

    [Fact]
    public void Case_sensitive_columns_are_not_citext()
    {
        var model = Model();

        foreach (var column in TextCaseSensitivity.CaseSensitiveByDesign.Keys)
        {
            var property = model.FindEntityType(column.Entity)?.FindProperty(column.Property);
            Assert.True(property is not null, $"{column} is registered but not in the model");

            Assert.NotEqual(TextCaseSensitivity.CaseInsensitiveColumnType, property!.GetColumnType());
        }
    }

    [Fact]
    public void The_citext_extension_is_declared_on_the_model()
    {
        // citext is a type, and a type that does not exist yet is a migration that fails on its
        // first table. The annotation is what puts CREATE EXTENSION at the top of InitialCreate.
        Assert.NotNull(Model().FindAnnotation(
            "Npgsql:PostgresExtension:" + TextCaseSensitivity.Extension));
    }

    [Fact]
    public void Converted_columns_keep_their_length_limit()
    {
        // citext takes no length modifier, so character varying(255) becomes an unbounded type on
        // the way across unless something puts the bound back. A check constraint does, and this
        // asserts it is there for every converted column that declared a maximum — otherwise the
        // case fix would quietly buy a 10,000-character username.
        var model = Model();

        foreach (var column in TextCaseSensitivity.CaseInsensitive)
        {
            var entityType = model.FindEntityType(column.Entity)!;
            var property = entityType.FindProperty(column.Property)!;
            if (property.GetMaxLength() is not int maxLength)
                continue;

            var expected = $"CK_{entityType.GetTableName()}_{property.GetColumnName()}_Length";
            var constraint = entityType.GetCheckConstraints().SingleOrDefault(c => c.Name == expected);

            Assert.True(constraint is not null,
                $"{column} is citext with a max length of {maxLength} but has no {expected} "
                + "constraint, so the database no longer enforces the limit");
            Assert.Contains(maxLength.ToString(), constraint!.Sql);
        }
    }

    // ── The columns whose loss would be loudest ────────────────────────────────

    [Theory]
    [InlineData(typeof(UserEntity), nameof(UserEntity.Username))]
    [InlineData(typeof(UserEntity), nameof(UserEntity.Email))]
    [InlineData(typeof(TenantEntity), nameof(TenantEntity.Slug))]
    [InlineData(typeof(CertificateAuthorityEntity), nameof(CertificateAuthorityEntity.Label))]
    [InlineData(typeof(TenantHostnameEntity), nameof(TenantHostnameEntity.Hostname))]
    [InlineData(typeof(KerberosRealmEntity), nameof(KerberosRealmEntity.Realm))]
    [InlineData(typeof(RoleEntity), nameof(RoleEntity.Name))]
    [InlineData(typeof(CaGroupEntity), nameof(CaGroupEntity.Name))]
    public void Identifiers_people_and_clients_type_stay_case_insensitive(Type entity, string property)
    {
        // Named individually rather than left to the set membership test, because these are the
        // ones where being wrong is not a tidiness problem: a sign-in that stops working, a CA
        // label in an enrollment URL that stops resolving, a Kerberos realm a client spells in
        // the case its resolver handed it, a role or group carrying half of somebody's rights.
        // Removing one from the registry should require deleting a line here that says why not.
        Assert.Contains(new TextCaseSensitivity.Column(entity, property), TextCaseSensitivity.CaseInsensitive);

        Assert.Equal(TextCaseSensitivity.CaseInsensitiveColumnType,
            Model().FindEntityType(entity)!.FindProperty(property)!.GetColumnType());
    }

    [Theory]
    [InlineData(typeof(RefreshTokenEntity), nameof(RefreshTokenEntity.Token))]
    [InlineData(typeof(AcmeNonceEntity), nameof(AcmeNonceEntity.Value))]
    [InlineData(typeof(AcmeAccountEntity), nameof(AcmeAccountEntity.JwkThumbprint))]
    [InlineData(typeof(Fido2CredentialEntity), nameof(Fido2CredentialEntity.CredentialId))]
    public void Secrets_and_base64_identifiers_stay_case_sensitive(Type entity, string property)
    {
        // The other direction, and the one MySQL had wrong. Folding case on a bearer token or a
        // base64url identifier is not a convenience; it shrinks the alphabet the value was drawn
        // from, and for a nonce or a thumbprint it invents collisions between distinct keys.
        // These columns must never be moved into the case-insensitive set for consistency.
        Assert.True(TextCaseSensitivity.CaseSensitiveByDesign.ContainsKey(
            new TextCaseSensitivity.Column(entity, property)));

        Assert.NotEqual(TextCaseSensitivity.CaseInsensitiveColumnType,
            Model().FindEntityType(entity)!.FindProperty(property)!.GetColumnType());
    }
}
