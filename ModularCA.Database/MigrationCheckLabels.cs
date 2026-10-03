namespace ModularCA.Database;

/// <summary>
/// The labels a migration's source gives its refusing checks (<c>// P1</c>, or a step number for a
/// check after a data step), in the order its commands raise them, so the dry run can name the
/// check that refused. A migration absent here has no labelled check. <c>MigrationCheckLabelsTests</c>
/// derives the table from the migration sources and fails when it is out of date.
/// </summary>
public static class MigrationCheckLabels
{
    /// <summary>Each labelled migration's check labels, one per command that can raise, in command order.</summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string?>> Labels =
        new Dictionary<string, IReadOnlyList<string?>>(StringComparer.Ordinal)
        {
            ["20260929051025_FoldSystemTenant"] = ["P1", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "7"],
            ["20261002063527_InstanceUniqueCaNames"] = ["P1", "P2", "P3", "P4", "P5"],
            ["20261003072435_RenameTenantToSpace"] = ["P1", "P2", "6"],
        };

    /// <summary>True when <paramref name="commandText"/> can refuse: it raises an exception.</summary>
    public static bool Raises(string commandText) =>
        commandText.Contains("RAISE EXCEPTION", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The check label of each of <paramref name="commandTexts"/>, the commands of
    /// <paramref name="migrationId"/> in order: the next label for each command that
    /// <see cref="Raises"/>, <see langword="null"/> for the others. All null when the migration has
    /// no labels, or when its raising commands do not match them one for one.
    /// </summary>
    public static IReadOnlyList<string?> ForCommands(string migrationId, IReadOnlyList<string> commandTexts)
    {
        ArgumentNullException.ThrowIfNull(commandTexts);
        var result = new string?[commandTexts.Count];
        if (!Labels.TryGetValue(migrationId, out var labels) || commandTexts.Count(Raises) != labels.Count)
            return result;
        var next = 0;
        for (var i = 0; i < commandTexts.Count; i++)
            if (Raises(commandTexts[i]))
                result[i] = labels[next++];
        return result;
    }
}
