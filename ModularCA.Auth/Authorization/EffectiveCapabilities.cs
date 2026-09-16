namespace ModularCA.Auth.Authorization;

/// <summary>
/// Everything a user may do, resolved once across all four grant sources and laid out the way
/// a client needs it: the capabilities held at system scope, and per certificate authority the
/// capabilities that apply there.
/// </summary>
/// <remarks>
/// <para>
/// This is the payload behind <c>GET /api/v1/me</c>'s <c>capabilities</c> field. The console
/// derives its navigation, its CA scope switcher and its page gates from it, so no role or
/// group template name has to be known on the client.
/// </para>
/// <para>
/// The resolution mirrors <see cref="ICaGroupAuthorizationService.HasCaCapabilityAsync"/>: a
/// holder of <c>system.manage</c> at system scope passes every CA-scoped check, so such a user
/// is reported as holding every capability at system scope and on every CA, rather than the
/// literal grants, which would understate what the API lets them do.
/// </para>
/// </remarks>
/// <param name="System">Capabilities held at system scope. These apply to every CA.</param>
/// <param name="Cas">Every CA on which the user holds at least one capability, ordered by label.</param>
public sealed record EffectiveCapabilities(
    IReadOnlyList<string> System,
    IReadOnlyList<CaCapabilities> Cas)
{
    /// <summary>An empty result: no capabilities anywhere.</summary>
    public static readonly EffectiveCapabilities None = new([], []);
}

/// <summary>
/// The capabilities a user holds on one certificate authority: the system-scoped ones, the
/// ones granted tenant-wide for the CA's tenant, and the ones granted on the CA itself.
/// </summary>
/// <param name="Id">The CA's id.</param>
/// <param name="Label">The CA's label, which is what a scope in a console URL names.</param>
/// <param name="Name">The CA's display name.</param>
/// <param name="IsSshCa">Whether this is an SSH CA rather than an X.509 one.</param>
/// <param name="TenantId">The tenant the CA belongs to; the console's tenant scope groups CAs by it.</param>
/// <param name="TenantName">The tenant's display name.</param>
/// <param name="TenantSlug">The tenant's slug, which is what a tenant scope in a console URL names.</param>
/// <param name="Capabilities">The capabilities that apply on this CA, sorted.</param>
public sealed record CaCapabilities(
    Guid Id,
    string Label,
    string Name,
    bool IsSshCa,
    Guid TenantId,
    string TenantName,
    string TenantSlug,
    IReadOnlyList<string> Capabilities);
