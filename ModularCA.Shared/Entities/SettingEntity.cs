using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// One instance-wide setting that has been set, under its catalog key (for example
/// <c>Acme_Http01_MaxAddresses</c>; see <c>SettingsCatalog</c>). A setting nobody has set has no
/// row and takes its built-in default, so a default a new build changes reaches every instance
/// that never chose a value.
/// </summary>
[Table("Settings")]
public class SettingEntity
{
    /// <summary>The catalog key. Written from the catalog and compared exactly.</summary>
    [Key]
    [MaxLength(200)]
    public string Key { get; set; } = string.Empty;

    /// <summary>
    /// The value as JSON of the setting's type, or null when the setting was set and later
    /// cleared back to its default. The row is kept so <see cref="Version"/> keeps counting.
    /// </summary>
    public string? ValueJson { get; set; }

    /// <summary>Counts the changes to this setting; what a writer names to detect a concurrent change.</summary>
    public int Version { get; set; }

    /// <summary>The instance-wide revision of the change that wrote this value.</summary>
    public long Revision { get; set; }

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public Guid? ActorId { get; set; }

    [MaxLength(256)]
    public string ActorName { get; set; } = string.Empty;

    /// <summary>How the change arrived: see <c>SettingsSource</c>.</summary>
    [MaxLength(32)]
    public string Source { get; set; } = string.Empty;
}

/// <summary>
/// One change to one setting. Append-only: a rollback is a new row whose value is an old one.
/// Every setting changed by one write carries that write's <see cref="Revision"/>.
/// </summary>
[Table("SettingsHistory")]
public class SettingHistoryEntity
{
    [Key]
    public long Id { get; set; }

    /// <summary>The instance-wide revision of the write this change belongs to.</summary>
    public long Revision { get; set; }

    [MaxLength(200)]
    public string Key { get; set; } = string.Empty;

    /// <summary>The setting's version after this change.</summary>
    public int Version { get; set; }

    /// <summary>The value written, as JSON; null when the setting was cleared back to its default.</summary>
    public string? ValueJson { get; set; }

    /// <summary>The value this change replaced, as JSON; null when the setting had none.</summary>
    public string? PreviousValueJson { get; set; }

    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;

    public Guid? ActorId { get; set; }

    [MaxLength(256)]
    public string ActorName { get; set; } = string.Empty;

    [MaxLength(32)]
    public string Source { get; set; } = string.Empty;

    /// <summary>Why the change was made, when the writer said.</summary>
    [MaxLength(1000)]
    public string? Reason { get; set; }
}

/// <summary>
/// The single row that orders every settings write. A write raises <see cref="Revision"/> by one
/// in the same save as its changes, and the row is a concurrency token, so two writes cannot
/// take the same revision: the second fails and is tried again from the current state.
/// </summary>
[Table("SettingsState")]
public class SettingsStateEntity
{
    /// <summary>The fixed id of the one row.</summary>
    public const int SingletonId = 1;

    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.None)]
    public int Id { get; set; } = SingletonId;

    /// <summary>The revision of the latest write; 0 before the first.</summary>
    [ConcurrencyCheck]
    public long Revision { get; set; }
}
