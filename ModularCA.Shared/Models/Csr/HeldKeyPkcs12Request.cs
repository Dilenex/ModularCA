using System.ComponentModel.DataAnnotations;

namespace ModularCA.Shared.Models.Csr;

/// <summary>
/// Request body for downloading an issued certificate together with the private key the CA
/// held for its request, as one PKCS#12 file.
/// </summary>
public class HeldKeyPkcs12Request
{
    /// <summary>The password the PKCS#12 is protected with. At least eight characters.</summary>
    [Required, MinLength(8), MaxLength(256)]
    public string Password { get; set; } = string.Empty;
}
