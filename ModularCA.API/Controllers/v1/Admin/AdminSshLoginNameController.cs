using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for SSH login names: the grants of an SSH CA key, what a user or a group
/// holds, a user's certificates, and finding a certificate from what a host logged. Every route
/// is fenced by the SSH CA key's certificate authority and its space: a route that names a key
/// answers 404 when the key is outside the caller's <see cref="SpaceFence"/>, and a route that
/// names none answers only for the keys the caller holds the capability on. Changing grants
/// needs ca.manage on the key's CA and step-up MFA; reading them needs cert.view. The rules,
/// the audit entries and the revocations are <see cref="ISshLoginNameService"/>'s.
/// </summary>
[ApiController]
[Route("api/v1/admin/ssh")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminSshLoginNameController(ISshLoginNameService loginNames, ICurrentUserService currentUser, ModularCADbContext db,
    ICaGroupAuthorizationService authService) : ControllerBase
{
    /// <summary>Who is asking, as the service records it in the audit and on a grant.</summary>
    private SshCaActor Actor() => new(currentUser.User?.Id, currentUser.User?.Username, HttpContext.Connection.RemoteIpAddress?.ToString());

    /// <summary>
    /// Whether <paramref name="caKeyId"/> is an SSH CA key whose certificate authority is inside
    /// the caller's fence for <paramref name="capability"/>. The policy on the action has already
    /// required the capability on that authority; a key that does not exist, or lies outside the
    /// fence, is not found.
    /// </summary>
    private async Task<bool> InFenceAsync(Guid caKeyId, string capability)
    {
        var key = await db.SshCaKeys.AsNoTracking().Where(k => k.Id == caKeyId)
            .Join(db.CertificateAuthorities.AsNoTracking(), k => k.CertificateAuthorityId, c => c.Id, (k, c) => new { c.SpaceId })
            .FirstOrDefaultAsync();
        return key != null && SpaceFence.From(HttpContext, capability).Allows(key.SpaceId);
    }

    /// <summary>
    /// The SSH CA keys the caller holds <paramref name="capability"/> on: the keys of the
    /// certificate authorities the capability is held on that are inside the caller's fence for it.
    /// </summary>
    private async Task<List<Guid>> KeysWithAsync(string capability)
    {
        if (currentUser.User == null)
            return [];
        var caIds = await authService.GetAccessibleCaIdsAsync(currentUser.User.Id, capability);
        if (caIds.Count == 0)
            return [];
        var fence = SpaceFence.From(HttpContext, capability);
        var keys = await db.SshCaKeys.AsNoTracking().Where(k => caIds.Contains(k.CertificateAuthorityId))
            .Join(db.CertificateAuthorities.AsNoTracking(), k => k.CertificateAuthorityId, c => c.Id, (k, c) => new { k.Id, c.SpaceId })
            .ToListAsync();
        return keys.Where(k => fence.Allows(k.SpaceId)).Select(k => k.Id).ToList();
    }

    /// <summary>
    /// The user a route names, when the caller may see them: an account with a membership, a
    /// role or a grant in a scope inside the caller's user.manage fence. Null otherwise, which
    /// the routes answer as not found, so an id cannot confirm an account of another space.
    /// </summary>
    private async Task<SshUserRef?> VisibleUserAsync(Guid userId)
    {
        var username = await db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => u.Username).FirstOrDefaultAsync();
        if (username == null)
            return null;
        var fence = SpaceFence.From(HttpContext, Capabilities.UserManage);
        if (!fence.InstanceWide && !(await loginNames.ScopesOfUserAsync(userId, HttpContext.RequestAborted)).Any(fence.Allows))
            return null;
        return new SshUserRef(userId, username);
    }

    // ---- The login names of a key ------------------------------------------------------------

    /// <summary>
    /// The login names of an SSH CA key: whether everyone may log in as their own username, and
    /// the grants, each with its login name, the user or the group it was made to (a group with
    /// its member count), its limit in hours, its end and whether it has ended, its note, who
    /// granted it and when, and how many live certificates name it in their grounds.
    /// </summary>
    [HttpGet("ca-keys/{caKeyId:guid}/login-names")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetLoginNames(Guid caKeyId)
    {
        if (!await InFenceAsync(caKeyId, Capabilities.CertView))
            return NotFound();
        var list = await loginNames.ListAsync(caKeyId, HttpContext.RequestAborted);
        return list == null ? NotFound() : Ok(list);
    }

    /// <summary>
    /// Grants login names on an SSH CA key to one user or one group, one grant per name. A name
    /// the target already has on the key is 409 naming it, and nothing is granted. A limit over
    /// the key's maximum, an end in the past, a name that is no login name, both or neither of
    /// <c>userId</c> and <c>groupId</c>, and a user or group the SSH CA may not refer to, are 400.
    /// </summary>
    [HttpPost("ca-keys/{caKeyId:guid}/login-names")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.ManageSshLoginNames, "caKeyId")]
    public async Task<IActionResult> GrantLoginNames(Guid caKeyId, [FromBody] GrantSshLoginNamesRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (!await InFenceAsync(caKeyId, Capabilities.CaManage))
            return NotFound();
        var grants = await loginNames.GrantAsync(caKeyId,
            new SshLoginNameGrantRequest(request.LoginNames ?? [], request.UserId, request.GroupId, request.MaxValidityHours, request.ExpiresAt, request.Note),
            Actor(), HttpContext.RequestAborted);
        return Ok(new { grants });
    }

    /// <summary>
    /// Changes a grant's limit, end and note; all three are set, and null clears one. Moving the
    /// end earlier revokes the certificates whose subject then no longer holds a name through
    /// their validity; lowering the limit revokes none. Answers the grant and how many
    /// certificates were revoked.
    /// </summary>
    [HttpPut("ca-keys/{caKeyId:guid}/login-names/{grantId:guid}")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.ManageSshLoginNames, "caKeyId")]
    public async Task<IActionResult> ChangeLoginNameGrant(Guid caKeyId, Guid grantId, [FromBody] ChangeSshLoginNameGrantRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (!await InFenceAsync(caKeyId, Capabilities.CaManage))
            return NotFound();
        var changed = await loginNames.ChangeGrantAsync(caKeyId, grantId,
            new SshLoginNameGrantChange(request.MaxValidityHours, request.ExpiresAt, request.Note), Actor(), HttpContext.RequestAborted);
        return changed == null ? NotFound() : Ok(changed);
    }

    /// <summary>
    /// Removes a grant, revokes the certificates whose subject then no longer holds a name, and
    /// answers how many were revoked.
    /// </summary>
    [HttpDelete("ca-keys/{caKeyId:guid}/login-names/{grantId:guid}")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.ManageSshLoginNames, "caKeyId")]
    public async Task<IActionResult> RemoveLoginNameGrant(Guid caKeyId, Guid grantId)
    {
        await currentUser.EnsureLoadedAsync();
        if (!await InFenceAsync(caKeyId, Capabilities.CaManage))
            return NotFound();
        var revoked = await loginNames.RemoveGrantAsync(caKeyId, grantId, Actor(), HttpContext.RequestAborted);
        return revoked == null ? NotFound() : Ok(new { revokedCertificates = revoked.Value });
    }

    /// <summary>
    /// Sets whether everyone may log in as their own username on an SSH CA key, without a grant.
    /// Turning it off revokes the certificates whose subject then no longer holds a name.
    /// </summary>
    [HttpPut("ca-keys/{caKeyId:guid}/login-names/own-username")]
    [Authorize(Policy = "CaAdmin")]
    [RequireStepUp(StepUpOps.ManageSshLoginNames, "caKeyId")]
    public async Task<IActionResult> SetOwnUsername(Guid caKeyId, [FromBody] SetSshOwnUsernameRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (request.Allowed == null)
            return BadRequest(new { error = "Say whether logging in as one's own username is allowed: { \"allowed\": true } or { \"allowed\": false }." });
        if (!await InFenceAsync(caKeyId, Capabilities.CaManage))
            return NotFound();
        var revoked = await loginNames.SetOwnUsernameAsync(caKeyId, request.Allowed.Value, Actor(), HttpContext.RequestAborted);
        return revoked == null ? NotFound() : Ok(new { allowOwnUsername = request.Allowed.Value, revokedCertificates = revoked.Value });
    }

    /// <summary>
    /// The login names one user holds on one SSH CA key, for signing a certificate for that user:
    /// each name with the ground that counts, its limit in hours and its end. Needs what the
    /// admin sign route needs, cert.revoke on the key's CA. A user who does not exist, is not
    /// active, or whom the SSH CA may not refer to is 404, as one answer.
    /// </summary>
    [HttpGet("ca-keys/{caKeyId:guid}/users/{userId:guid}/login-names")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetUserLoginNamesOnKey(Guid caKeyId, Guid userId)
    {
        if (!await InFenceAsync(caKeyId, Capabilities.CertRevoke))
            return NotFound();
        var user = await db.Users.AsNoTracking().Where(u => u.Id == userId && u.IsActive).Select(u => new { u.Id, u.Username }).FirstOrDefaultAsync();
        if (user == null || !await loginNames.MayReferenceUserAsync(caKeyId, userId, HttpContext.RequestAborted))
            return NotFound();
        var held = await loginNames.HeldAsync(userId, caKeyId, HttpContext.RequestAborted);
        return Ok(new
        {
            user = new SshUserRef(user.Id, user.Username),
            loginNames = held.Select(h => new SshRequestLoginName(h.Name, h.Ground.Source, h.Ground.GrantId, h.Ground.GroupId, h.Ground.GroupName,
                h.MaxValidityHours, h.ExpiresAt)),
        });
    }

    // ---- What a user or a group holds --------------------------------------------------------

    /// <summary>
    /// Every ground on which a user holds a login name, on the SSH CA keys the caller holds
    /// cert.view on: the key, the name, where it comes from (<c>own</c>, <c>user</c>,
    /// <c>group</c>), the grant and the group, its limit in hours and its end. Needs user.manage,
    /// and a user inside the caller's user.manage fence; otherwise 404.
    /// </summary>
    [HttpGet("users/{userId:guid}/login-names")]
    [Authorize]
    [RequireCaCapability(Capabilities.UserManage, CaTarget.AnyCa)]
    public async Task<IActionResult> GetUserLoginNames(Guid userId)
    {
        await currentUser.EnsureLoadedAsync();
        if (await VisibleUserAsync(userId) is not { } user)
            return NotFound();
        var names = await loginNames.NamesOfUserAsync(userId, await KeysWithAsync(Capabilities.CertView), HttpContext.RequestAborted);
        return Ok(new { user, loginNames = names });
    }

    /// <summary>
    /// The login names granted to a group, on the SSH CA keys the caller holds cert.view on. A
    /// group outside the caller's cert.view fence is 404.
    /// </summary>
    [HttpGet("groups/{groupId:guid}/login-names")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetGroupLoginNames(Guid groupId)
    {
        await currentUser.EnsureLoadedAsync();
        var group = await db.CaGroups.AsNoTracking().Where(g => g.Id == groupId)
            .Select(g => new { g.Id, g.Name, g.DisplayName, g.SpaceId, MemberCount = g.Members.Count })
            .FirstOrDefaultAsync();
        if (group == null || !SpaceFence.From(HttpContext, Capabilities.CertView).Allows(group.SpaceId))
            return NotFound();
        var grants = await loginNames.GrantsOfGroupAsync(groupId, await KeysWithAsync(Capabilities.CertView), HttpContext.RequestAborted);
        return Ok(new { group = new SshGroupRef(group.Id, group.Name, group.DisplayName, group.MemberCount), grants });
    }

    /// <summary>
    /// The SSH certificates issued for a user, on the SSH CA keys the caller holds cert.view on,
    /// newest first; with <c>live=true</c> only the unexpired, unrevoked ones. Needs user.manage,
    /// and a user inside the caller's user.manage fence; otherwise 404.
    /// </summary>
    [HttpGet("users/{userId:guid}/certificates")]
    [Authorize]
    [RequireCaCapability(Capabilities.UserManage, CaTarget.AnyCa)]
    public async Task<IActionResult> GetUserCertificates(Guid userId, [FromQuery] bool live = false)
    {
        await currentUser.EnsureLoadedAsync();
        if (await VisibleUserAsync(userId) == null)
            return NotFound();
        return Ok(await loginNames.CertificatesOfUserAsync(userId, await KeysWithAsync(Capabilities.CertView), live, HttpContext.RequestAborted));
    }

    /// <summary>
    /// Revokes the live SSH certificates issued for a user on the SSH CA keys the caller holds
    /// cert.revoke on, and answers how many were revoked and how many live ones were left
    /// because the caller may not revoke on their key. Needs user.manage, step-up MFA, and a
    /// user inside the caller's user.manage fence; otherwise 404.
    /// </summary>
    [HttpPost("users/{userId:guid}/certificates/revoke")]
    [Authorize]
    [RequireCaCapability(Capabilities.UserManage, CaTarget.AnyCa)]
    [RequireStepUp(StepUpOps.RevokeSshCert, "userId")]
    public async Task<IActionResult> RevokeUserCertificates(Guid userId)
    {
        await currentUser.EnsureLoadedAsync();
        if (await VisibleUserAsync(userId) == null)
            return NotFound();
        var result = await loginNames.RevokeCertificatesOfUserAsync(userId, await KeysWithAsync(Capabilities.CertRevoke), Actor(), HttpContext.RequestAborted);
        return Ok(new { revoked = result.Revoked, leftForRights = result.LeftForRights });
    }

    // ---- Finding a certificate ---------------------------------------------------------------

    /// <summary>
    /// Finds certificates from what a host logged with a login: the serial, required; the SSH CA
    /// key's fingerprint as <c>sshd</c> prints it (<c>SHA256:...</c>) and the key id narrow it.
    /// Searches the SSH CA keys the caller holds cert.view on, and answers each certificate with
    /// its key. The console reads the log line; the server takes the three values.
    /// </summary>
    [HttpGet("certificates/find")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> FindCertificates([FromQuery] long? serial = null, [FromQuery] string? caFingerprint = null, [FromQuery] string? keyId = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (serial == null)
            return BadRequest(new { error = "serial is required: the number sshd logs as (serial N)." });
        return Ok(await loginNames.FindCertificatesAsync(serial.Value, caFingerprint, keyId, await KeysWithAsync(Capabilities.CertView), HttpContext.RequestAborted));
    }

    /// <summary>
    /// One issued SSH certificate, on an SSH CA key the caller holds cert.view on: its row, who
    /// it is for, who issued it, and why its subject held each login name. Otherwise 404.
    /// </summary>
    [HttpGet("certificates/{id:guid}")]
    [Authorize(Policy = "CaAuditor")]
    public async Task<IActionResult> GetCertificate(Guid id)
    {
        await currentUser.EnsureLoadedAsync();
        var certificate = await db.SshCertificates.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
        if (certificate == null || !(await KeysWithAsync(Capabilities.CertView)).Contains(certificate.SshCaKeyId))
            return NotFound();
        return Ok((await loginNames.DescribeAsync([certificate], HttpContext.RequestAborted))[0]);
    }
}

/// <summary>Request model for granting SSH login names on an SSH CA key. It names exactly one of <see cref="UserId"/> and <see cref="GroupId"/>.</summary>
public class GrantSshLoginNamesRequest
{
    /// <summary>The login names to grant; one grant is made per name.</summary>
    public List<string>? LoginNames { get; set; }
    /// <summary>The user to grant them to.</summary>
    public Guid? UserId { get; set; }
    /// <summary>The group to grant them to; its members hold the names while they are members.</summary>
    public Guid? GroupId { get; set; }
    /// <summary>The longest certificate that may carry a name under these grants, in hours; omitted, the key's maximum.</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>When the grants end, UTC; omitted, they do not end. No certificate under them is valid past this.</summary>
    public DateTime? ExpiresAt { get; set; }
    /// <summary>A note, at most 256 characters.</summary>
    public string? Note { get; set; }
}

/// <summary>Request model for changing an SSH login name grant. All three members are set: null clears one.</summary>
public class ChangeSshLoginNameGrantRequest
{
    /// <summary>The limit in hours; null for the key's maximum.</summary>
    public int? MaxValidityHours { get; set; }
    /// <summary>When the grant ends, UTC; null when it does not end.</summary>
    public DateTime? ExpiresAt { get; set; }
    /// <summary>A note, at most 256 characters; null for none.</summary>
    public string? Note { get; set; }
}

/// <summary>Request model for allowing or refusing one's own username as a login name on an SSH CA key.</summary>
public class SetSshOwnUsernameRequest
{
    /// <summary>Whether everyone may log in as their own username without a grant.</summary>
    public bool? Allowed { get; set; }
}
