using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Interfaces;

public interface ISshCaService
{
    Task<SshCaKeyEntity> GenerateKeyPairAsync(string name, string keyType, bool isUserCa, bool isHostCa, int maxValidityHours, int? keySize = null);
    /// <summary>
    /// Disables an SSH CA key and revokes all active certificates issued by it.
    /// </summary>
    Task DisableAsync(Guid caKeyId);
    Task<SshCertificateEntity> SignUserKeyAsync(Guid caKeyId, string publicKey, List<string> principals, int? validityHours, string? keyId, List<string>? extensions, Guid? issuedByUserId, string? sourceIp);
    Task<SshCertificateEntity> SignHostKeyAsync(Guid caKeyId, string publicKey, List<string> hostnames, int? validityHours, string? keyId, Guid? issuedByUserId, string? sourceIp);
    Task<string> GetPublicKeyAsync(Guid caKeyId);
    Task<List<SshCaKeyEntity>> GetCaKeysAsync();
    /// <summary>
    /// Lists issued SSH certificates, optionally filtered by CA key.
    /// </summary>
    Task<List<SshCertificateEntity>> GetCertificatesAsync(int page = 1, int pageSize = 50, Guid? caKeyId = null, string? sort = null);
    Task<bool> RevokeCertificateAsync(Guid certId, Guid? requiredCaKeyId = null);
    Task<SshCertificateEntity?> GetCertificateByIdAsync(Guid certId);
    Task<byte[]> GenerateKrlAsync(Guid caKeyId);
}
