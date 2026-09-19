using MySqlConnector;
using Npgsql;

namespace ModularCA.Migrate;

/// <summary>
/// The MariaDB to PostgreSQL migration helper.
/// <para>
/// A separate command rather than something the node does at startup, because it runs while
/// nothing else is running and because its failure has to be loud. It never writes to the source,
/// which is what makes the rollback story "reinstall 0.3.0 and point it back at MariaDB" rather
/// than anything this program has to implement.
/// </para>
/// <para>
/// The order below is the whole design: everything before the copy is reversible by dropping what
/// this run created, and the run refuses before it creates anything at all unless every check
/// passes.
/// </para>
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // Only an explicit request prints the usage. No arguments at all is the ordinary
        // invocation — the whole point of reading db.yaml and borrowing a role is that a
        // deployment needs to say nothing — and treating it as "you forgot something" made the
        // one command this tool documents do nothing but describe itself.
        if (CommandLine.WantsUsage(args))
        {
            Usage();
            return 0;
        }

        MigrationOptions options;
        try
        {
            options = CommandLine.Parse(args);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"(!) {ex.Message}");
            Console.Error.WriteLine("    Run with --help for the full list of options.");
            return 2;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };

        Banner(options);

        // No administrative credentials given: on a host where the operating system already
        // trusts us with the database, borrow a role for the run rather than making the operator
        // invent one. Disposed on every path, so the role never outlives the command.
        await using var borrowed = await BorrowAdminRoleAsync(options, cancellation.Token);
        if (borrowed is null && options.TargetAdminUser.Length == 0)
            return 2;

        try
        {
            return await RunAsync(options, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("\n(!) Cancelled.");
            return 130;
        }
    }

    /// <summary>
    /// Says what is about to be migrated, and where the source was read from.
    /// </summary>
    /// <param name="options">The resolved options.</param>
    private static void Banner(MigrationOptions options)
    {
        Console.WriteLine(
            $"ModularCA database migration — MariaDB {options.SourceHost}:{options.SourcePort} "
            + $"to PostgreSQL {options.TargetHost}:{options.TargetPort}");
        if (options.ConfigPath is not null)
            Console.WriteLine($"Source read from {options.ConfigPath}");
        Console.WriteLine();
    }

    /// <summary>
    /// Fills in the administrative account when none was supplied, by creating a temporary role
    /// through the local socket. Returns null when nothing was borrowed: either because
    /// credentials were given, or because this host cannot do it, in which case the single
    /// statement to run instead is printed.
    /// </summary>
    /// <param name="options">The options to complete.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The borrowed access to dispose, or null.</returns>
    private static async Task<LocalPostgresAccess?> BorrowAdminRoleAsync(
        MigrationOptions options, CancellationToken ct)
    {
        if (options.TargetAdminUser.Length > 0)
            return null;

        if (!LocalPostgresAccess.IsAvailable())
        {
            Console.Error.WriteLine(
                "(!) No PostgreSQL administrative account was given, and this host cannot provide");
            Console.Error.WriteLine(
                "    one automatically (that needs Linux, root, and psql on the path).");
            Console.Error.WriteLine("");
            Console.Error.WriteLine("    Create one:");
            Console.Error.WriteLine("");
            foreach (var line in LocalPostgresAccess.ManualInstructions().Split('\n'))
                Console.Error.WriteLine("      " + line);
            return null;
        }

        try
        {
            var access = await LocalPostgresAccess.AcquireAsync(Console.WriteLine, ct);
            options.TargetAdminUser = access.User;
            options.TargetAdminPassword = access.Password;
            return access;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine("(!) " + ex.Message);
            Console.Error.WriteLine("");
            Console.Error.WriteLine("    Or create an account by hand:");
            Console.Error.WriteLine("");
            foreach (var line in LocalPostgresAccess.ManualInstructions().Split('\n'))
                Console.Error.WriteLine("      " + line);
            return null;
        }
    }

    private static async Task<int> RunAsync(MigrationOptions options, CancellationToken ct)
    {
        void Say(string line) => Console.WriteLine(line);

        // ── 1. Preflight ──────────────────────────────────────────────────────
        Say("Preflight");
        var preflight = new Preflight(options);
        var ok = await preflight.RunAsync(ct);

        foreach (var note in preflight.Notes)
            Say($"  {note}");

        if (!ok)
        {
            Say("");
            Console.Error.WriteLine($"Refusing to migrate. {preflight.Refusals.Count} problem(s) to resolve:");
            foreach (var refusal in preflight.Refusals)
                Console.Error.WriteLine($"  - {refusal}");
            Console.Error.WriteLine("");
            Console.Error.WriteLine("Nothing was created and the source was not touched.");
            return 1;
        }

        Say("  every check passed");
        Say("");

        if (options.DryRun)
        {
            Say("Dry run: stopping here. Nothing was created.");
            return 0;
        }

        // ── 2. Build the destination ──────────────────────────────────────────
        var builder = new DestinationBuilder(options, Say);
        try
        {
            Say("Creating the destination");
            await builder.BuildAsync(ct);
            Say("");

            // ── 3. Copy ───────────────────────────────────────────────────────
            Say("Copying the application database");
            var appResults = await CopyDatabaseAsync(
                options, options.SourceAppDatabase, builder.AppPassword,
                ModelIntrospection.Tables(ModelIntrospection.DestinationModel()),
                options.AppInstance(builder.AppPassword), Say, ct);
            Say("");

            Say("Copying the audit database");
            var auditResults = await CopyDatabaseAsync(
                options, options.SourceAuditDatabase, builder.AuditPassword,
                ModelIntrospection.Tables(ModelIntrospection.AuditModel()),
                options.AuditInstance(builder.AuditPassword), Say, ct);
            Say("");

            // ── 4. Verify ─────────────────────────────────────────────────────
            Say("Verifying");
            var verification = new Verification(Say);

            await using (var appConn = new NpgsqlConnection(
                Shared.Utils.PostgresConnection.Build(options.AppInstance(builder.AppPassword))))
            {
                await appConn.OpenAsync(ct);
                await verification.ResetSequencesAsync(appConn, ct);
                await verification.CheckRowCountsAsync(appConn, appResults, ct);
                await verification.CheckCertificatesAsync(appConn, sample: 50, ct);
            }

            await using (var auditConn = new NpgsqlConnection(
                Shared.Utils.PostgresConnection.Build(options.AuditInstance(builder.AuditPassword))))
            {
                await auditConn.OpenAsync(ct);
                await verification.ResetSequencesAsync(auditConn, ct);
                await verification.CheckRowCountsAsync(auditConn, auditResults, ct);
            }

            await using (var auditDb = DestinationBuilder.AuditContext(options.AuditInstance(builder.AuditPassword)))
            await using (var auditSource = new MySqlConnection(
                options.SourceConnectionString(options.SourceAuditDatabase)))
            {
                await auditSource.OpenAsync(ct);
                await verification.CheckAuditChainAsync(auditDb, auditSource, ct);
            }

            if (verification.Failures.Count > 0)
            {
                Console.Error.WriteLine("");
                Console.Error.WriteLine($"Verification failed. {verification.Failures.Count} problem(s):");
                foreach (var failure in verification.Failures)
                    Console.Error.WriteLine($"  - {failure}");
                throw new MigrationFailedException("verification failed");
            }

            // Only now, with every check passed. A db.yaml pointing at a database that failed
            // verification would be worse than one still pointing at MariaDB.
            var config = ConfigUpdate.Apply(
                options, builder.AppPassword, builder.AuditPassword, DateTime.Now);

            Say("");
            Report(options, builder, appResults, auditResults, config, Say);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("");
            Console.Error.WriteLine($"(!) Migration failed: {ex.Message}");

            // Cleanup runs whatever stage failed, including one that failed partway through
            // creating things. An earlier version only cleaned up once the whole creation step
            // had succeeded, so a failure in the middle of it left roles behind while reporting
            // that nothing had been created — and the next run then refused, correctly, on names
            // that were only taken because of the first one. Every statement in the rollback is
            // IF EXISTS and names only what preflight proved was free, so running it when there
            // is nothing to remove costs nothing.
            if (options.KeepOnFailure)
            {
                Console.Error.WriteLine(
                    $"    The half-built databases '{options.TargetAppDatabase}' and "
                    + $"'{options.TargetAuditDatabase}' were left in place for inspection (--keep-on-failure). "
                    + "Drop them before re-running.");
                return 1;
            }

            // Safe only because preflight refused unless none of this existed: everything dropped
            // here was created by this run, or was never there.
            Console.Error.WriteLine("    Removing anything this run created:");
            await DestinationBuilder.RollbackAsync(options, l => Console.Error.WriteLine($"  {l}"), CancellationToken.None);
            Console.Error.WriteLine("    The source was not touched. Fix the problem above and run again.");
            return 1;
        }
    }

    private static async Task<IReadOnlyList<TableCopier.TableResult>> CopyDatabaseAsync(
        MigrationOptions options, string sourceDatabase, string destPassword,
        IReadOnlyList<ModelIntrospection.TableInfo> tables,
        Shared.Models.Config.DbInstance destInstance, Action<string> say, CancellationToken ct)
    {
        await using var source = new MySqlConnection(options.SourceConnectionString(sourceDatabase));
        await source.OpenAsync(ct);

        await using var dest = new NpgsqlConnection(Shared.Utils.PostgresConnection.Build(destInstance));
        await dest.OpenAsync(ct);

        return await new TableCopier(say).CopyAsync(source, dest, tables, ct);
    }

    private static void Report(
        MigrationOptions options, DestinationBuilder builder,
        IReadOnlyList<TableCopier.TableResult> app, IReadOnlyList<TableCopier.TableResult> audit,
        ConfigUpdate.Result config, Action<string> say)
    {
        var copied = app.Concat(audit).ToList();
        say("Done.");
        say("");
        say($"  {copied.Count(r => !r.Skipped)} tables copied, "
            + $"{copied.Sum(r => r.CopiedRows):N0} rows total "
            + $"({copied.Count(r => r.Skipped)} tables were empty or new in 0.3.1)");
        say("");
        say("  Checked: foreign keys validated by the server, row counts per table, identity");
        say("  sequences reset, certificates re-parsed from their stored bytes, audit hash chain.");
        say("");
        say("  The source database was not modified. It remains a complete rollback.");
        say("");

        if (config.Any)
        {
            // The passwords are deliberately not printed. They are in the files, the files are
            // owner-only, and a terminal is a worse place for them than a shell history is.
            say("  These now name the PostgreSQL databases:");
            foreach (var file in config.Written)
                say($"    {file}");
            say("");
            say("  The MariaDB settings were kept at:");
            foreach (var backup in config.Backups)
                say($"    {backup}");
            say("");
            say("Start the node:");
            say("");
            say("  sudo systemctl start modularca");
            say("");
            say("To go back to 0.3.0: restore those backups over their originals and reinstall");
            say("0.3.0. The MariaDB database is untouched and still holds everything.");
            return;
        }

        say($"  The configuration was not updated ({config.Reason}).");
        say("  db.yaml — App and Audit are top level, with nothing above them:");
        say("");
        // Rendered by the same writer the node reads with, so the shape cannot drift from what
        // the deserializer expects. An earlier version printed these nested under a "DB:" key
        // that db.yaml has never had; the node then matched no properties, fell back to an empty
        // username and password, and failed to connect with an error naming neither.
        foreach (var line in ConfigUpdate.Render(options, builder.AppPassword, builder.AuditPassword)
                     .Split('\n'))
        {
            say("  " + line.TrimEnd());
        }

        say("");
        say("  config.yaml — the same settings again, under a DB: key, alongside everything else");
        say("  already in that file:");
        say("");
        foreach (var line in ConfigYamlDbSection
                     .Render(ConfigYamlDbSection.From(options, builder.AppPassword, builder.AuditPassword))
                     .Split('\n'))
        {
            say("  " + line.TrimEnd());
        }

        say("");
        say("  Both files need them. These passwords are shown once and are not stored");
        say("  anywhere by this program.");
    }

    private static void Usage()
    {
        Console.WriteLine("""
            modularca-migrate — copies a ModularCA 0.3.0 MariaDB database into a new PostgreSQL one.

            The supported upgrade path has three steps, and this is the second:
              1. Upgrade the deployment to 0.3.0 on MariaDB.
              2. Stop the node and run this.
              3. Start 0.3.1 against the PostgreSQL database this produced.

            On the machine the deployment runs on, this is the whole command:

                sudo modularca-migrate --dry-run     # check everything, create nothing
                sudo modularca-migrate               # do it

            It reads the source from the deployment's own db.yaml, defaults the destination to a
            PostgreSQL on the same host with the same database names, and borrows a temporary
            administrative role through the local socket. Everything below is an override, for
            the cases where one of those is not true.

            Source (read only, never written; taken from db.yaml unless overridden):
              --config <path>                 db.yaml, if it is somewhere unusual
              --source-host <host>            MariaDB host
              --source-port <port>            default 3306
              --source-user <user>            needs SELECT on both databases
              --source-password <password>
              --source-app-db <name>          the 0.3.0 application database
              --source-audit-db <name>        the 0.3.0 audit database
              --source-audit-user <user>      only if the audit account differs from the app one
              --source-audit-password <password>

            Destination (created by this program, so neither database nor role may exist):
              --target-host <host>            default 127.0.0.1
              --target-port <port>            default 5432
              --target-admin-user <user>      needs CREATEDB and CREATEROLE, nothing more
              --target-admin-password <password>
              --target-ssl-mode <mode>        disable|allow|prefer|require|verify-ca|verify-full
              --target-app-db <name>          defaults to the source application database name
              --target-audit-db <name>        defaults to the source audit database name
              --target-app-role <name>        defaults to the source application account
              --target-audit-role <name>      defaults to the source audit account
              --target-audit-owner-role <name>
                                              owns the audit database and cannot log in, so the
                                              node cannot drop its own audit; defaults to the
                                              audit role name with _owner appended

            Options:
              --dry-run                       run every check and stop before creating anything
              --keep-on-failure               leave a failed run's databases for inspection
              --no-write-config               do not update db.yaml; print the settings instead
              -h, --help                      this text

            The source is never written to, so a failed or unwanted migration is undone by
            starting 0.3.0 against MariaDB again.
            """);
    }
}

/// <summary>Raised when a stage fails in a way that should trigger the rollback path.</summary>
public sealed class MigrationFailedException : Exception
{
    /// <summary>Creates the exception with a reason.</summary>
    /// <param name="message">What failed.</param>
    public MigrationFailedException(string message) : base(message) { }
}
