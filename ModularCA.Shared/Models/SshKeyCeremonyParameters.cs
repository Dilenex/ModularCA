namespace ModularCA.Shared.Models;

/// <summary>
/// Parameters for SSH CA key ceremonies (CreateSshCa, DeleteSshCa).
/// Serialized to the same ParametersJson column as KeyCeremonyParameters
/// but deserialized based on OperationType.
/// </summary>
public class SshKeyCeremonyParameters
{
    public string Name { get; set; } = string.Empty;
    public string KeyType { get; set; } = "ed25519";
    public int? KeySize { get; set; }
    public bool IsUserCa { get; set; }
    public bool IsHostCa { get; set; }
    public int MaxValidityHours { get; set; } = 720;

    /// <summary>The SSH CA's space; null for an instance SSH CA. <see cref="Guid.Empty"/> reads as null.</summary>
    public Guid? SpaceId { get => _spaceId; set => _spaceId = value == Guid.Empty ? null : value; }
    private Guid? _spaceId;

    public Guid? SshCaKeyId { get; set; }
}
