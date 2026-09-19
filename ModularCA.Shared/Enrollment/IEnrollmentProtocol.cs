namespace ModularCA.Shared.Enrollment;

/// <summary>
/// What a protocol declares about itself. The adapter side of the enrollment contract: a protocol
/// implements this and calls <c>IEnrollmentPipeline</c> for the shared middle, keeping only its
/// parsing, its authentication and its rendering.
/// </summary>
/// <remarks>
/// This is a design boundary, not a loader: protocols are compiled in and registered.
/// </remarks>
public interface IEnrollmentProtocol
{
    /// <summary>
    /// The protocol name as it appears in per-CA protocol configuration and audit rows —
    /// <c>"ACME"</c>, <c>"EST"</c>, <c>"SCEP"</c>, <c>"CMP"</c>, <c>"MSAE"</c>. Upper case, because
    /// that is the form <c>CaProtocolConfigEntity.Protocol</c> stores.
    /// </summary>
    string Name { get; }

    /// <summary>What this protocol can do; see <see cref="EnrollmentCapabilities"/>.</summary>
    EnrollmentCapabilities Capabilities { get; }
}
