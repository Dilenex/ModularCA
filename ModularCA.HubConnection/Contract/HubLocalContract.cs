using System.Text.Json;
using System.Text.Json.Serialization;

namespace ModularCA.HubConnection.Contract;

/// <summary>
/// The contract of the hub's local connection: JSON over HTTP/1.1 on a Unix domain socket the
/// node listens on. This class holds the version, the operations and their routes, the request
/// headers and the error codes; the request and response bodies are the records beside it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Versions.</b> <see cref="Version"/> is <c>major.minor</c>. Within a major version the
/// contract only grows: operations and optional fields are added, none is removed or changes
/// meaning, and both sides ignore fields they do not know. Each side states its version and the
/// operations it has (<see cref="HubHello"/>), and every request names the hub's version in
/// <see cref="ContractHeader"/>; a request of another major version is refused
/// <see cref="Errors.ContractVersionUnsupported"/>.
/// </para>
/// <para>
/// <b>Proof.</b> Every request carries the affiliation token as <c>Authorization: Bearer</c>.
/// The instance holds only the token's SHA-256 and compares in constant time. While the instance
/// holds no hash the check is off and reaching the socket is the only proof; the health answer
/// and the hello say which (<see cref="TokenCheckEnforced"/>, <see cref="TokenCheckOff"/>).
/// </para>
/// <para>
/// <b>Once.</b> A request that changes something carries <see cref="RequestIdHeader"/>. The same
/// identifier sent again for the same operation and body is answered with the first answer and
/// <see cref="ReplayedHeader"/>, and nothing is done a second time.
/// </para>
/// </remarks>
public static class HubLocalContract
{
    /// <summary>This build's contract version.</summary>
    public const string Version = "1.1";

    /// <summary>The major version, which both sides must share.</summary>
    public const int MajorVersion = 1;

    /// <summary>The request header that names the hub's contract version. Required.</summary>
    public const string ContractHeader = "X-ModularCA-Hub-Contract";

    /// <summary>The request header that identifies a request so that a repeat is done once. Required on requests that change something.</summary>
    public const string RequestIdHeader = "X-ModularCA-Hub-Request-Id";

    /// <summary>The request header that carries the name of the person at the hub. Optional; recorded as the hub's claim, never trusted.</summary>
    public const string OperatorHeader = "X-ModularCA-Hub-Operator";

    /// <summary>The response header, <c>true</c>, on an answer that repeats an earlier one for the same request identifier.</summary>
    public const string ReplayedHeader = "X-ModularCA-Hub-Replayed";

    /// <summary>The longest request identifier and operator name accepted.</summary>
    public const int MaxHeaderValueLength = 128;

    /// <summary>The largest request body accepted, in bytes.</summary>
    public const int MaxBodyBytes = 16 * 1024;

    /// <summary><see cref="HubHealth.TokenCheck"/> when the instance holds a hash and checks every request against it.</summary>
    public const string TokenCheckEnforced = "enforced";

    /// <summary><see cref="HubHealth.TokenCheck"/> when the instance holds no hash, so reaching the socket is the only proof.</summary>
    public const string TokenCheckOff = "off";

    /// <summary>The operations of this contract version, by name.</summary>
    public static class Operations
    {
        /// <summary>Each side states its contract version and operations. <c>POST /hub/v1/hello</c>.</summary>
        public const string Hello = "hello";
        /// <summary>Read health as the instance sees it, with the mode and who set it. <c>GET /hub/v1/health</c>.</summary>
        public const string HealthRead = "health.read";
        /// <summary>Read the mode and who set it. <c>GET /hub/v1/mode</c>.</summary>
        public const string ModeRead = "mode.read";
        /// <summary>Set the mode. <c>PUT /hub/v1/mode</c>.</summary>
        public const string ModeSet = "mode.set";
        /// <summary>Ask for a backup now. <c>POST /hub/v1/backup</c>.</summary>
        public const string BackupCreate = "backup.create";
        /// <summary>Replace the affiliation token: the old token authorises the request, the new token's hash is in the body. <c>PUT /hub/v1/affiliation-token</c>.</summary>
        public const string AffiliationTokenReplace = "affiliation-token.replace";
        /// <summary>Read what the instance holds and how it stands: versions, the signer, expiries, the newest backup, failing jobs and the CAs. Since 1.1. <c>GET /hub/v1/inventory</c>.</summary>
        public const string InventoryRead = "inventory.read";
        /// <summary>Delete old backup archives from the instance's backup directory, keeping the newest. Since 1.1. <c>POST /hub/v1/backup/prune</c>.</summary>
        public const string BackupPrune = "backup.prune";

        /// <summary>Every operation of this version.</summary>
        public static IReadOnlyList<string> All { get; } = [Hello, HealthRead, ModeRead, ModeSet, BackupCreate, AffiliationTokenReplace, InventoryRead, BackupPrune];
    }

    /// <summary>The route of each operation.</summary>
    public static class Paths
    {
        /// <summary>The prefix of every route.</summary>
        public const string Prefix = "/hub/v1";
        /// <summary><see cref="Operations.Hello"/>.</summary>
        public const string Hello = Prefix + "/hello";
        /// <summary><see cref="Operations.HealthRead"/>.</summary>
        public const string Health = Prefix + "/health";
        /// <summary><see cref="Operations.ModeRead"/> (GET) and <see cref="Operations.ModeSet"/> (PUT).</summary>
        public const string Mode = Prefix + "/mode";
        /// <summary><see cref="Operations.BackupCreate"/>.</summary>
        public const string Backup = Prefix + "/backup";
        /// <summary><see cref="Operations.AffiliationTokenReplace"/>.</summary>
        public const string AffiliationToken = Prefix + "/affiliation-token";
        /// <summary><see cref="Operations.InventoryRead"/>.</summary>
        public const string Inventory = Prefix + "/inventory";
        /// <summary><see cref="Operations.BackupPrune"/>.</summary>
        public const string BackupPrune = Prefix + "/backup/prune";
    }

    /// <summary>The mode names of <see cref="HubMode.Mode"/> and <see cref="HubSetModeRequest.Mode"/>.</summary>
    public static class Modes
    {
        /// <summary>Everything is allowed.</summary>
        public const string Full = "full";
        /// <summary>New facts and restrictions only.</summary>
        public const string Restricted = "restricted";
        /// <summary>DR mode: signing in to manage and repair, and nothing else.</summary>
        public const string DisasterRecovery = "dr";

        /// <summary>Maintenance: nothing is issued or reconfigured; revoking, CRLs and OCSP go on.</summary>
        public const string Maintenance = "maintenance";
    }

    /// <summary>The <see cref="HubError.Error"/> codes.</summary>
    public static class Errors
    {
        /// <summary>401. The instance holds a hash and the request carried no token.</summary>
        public const string TokenRequired = "token_required";
        /// <summary>401. The token's SHA-256 is not the hash the instance holds.</summary>
        public const string TokenInvalid = "token_invalid";
        /// <summary>404. The method and path are not an operation of this contract version.</summary>
        public const string OperationNotListed = "operation_not_listed";
        /// <summary>400. The contract header is missing, unreadable, or of another major version.</summary>
        public const string ContractVersionUnsupported = "contract_version_unsupported";
        /// <summary>400. A request that changes something carried no usable request identifier.</summary>
        public const string RequestIdRequired = "request_id_required";
        /// <summary>409. The request identifier was already used for a different operation or body.</summary>
        public const string RequestIdReused = "request_id_reused";
        /// <summary>400. The body or a header is not what the operation takes.</summary>
        public const string InvalidRequest = "invalid_request";
        /// <summary>500. The backup did not complete.</summary>
        public const string BackupFailed = "backup_failed";
        /// <summary>500. The instance failed to carry out the request.</summary>
        public const string InternalError = "internal_error";
    }

    /// <summary>The JSON options of the wire: camelCase names, nulls left out, unknown fields ignored.</summary>
    public static JsonSerializerOptions Json { get; } = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Whether <paramref name="version"/> is a contract version this build can speak with: the
    /// form <c>major.minor</c> with this build's major.
    /// </summary>
    /// <param name="version">The other side's version.</param>
    public static bool IsCompatible(string? version)
    {
        var parts = version?.Trim().Split('.');
        return parts is { Length: 2 }
            && int.TryParse(parts[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var major)
            && int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _)
            && major == MajorVersion;
    }
}

/// <summary>What one side has: the body of <c>POST /hub/v1/hello</c> (the hub's) and its answer (the instance's).</summary>
/// <param name="ContractVersion">The side's contract version, <c>major.minor</c>.</param>
/// <param name="Operations">The operations the side has, by name.</param>
/// <param name="InstanceVersion">The instance's product version. Null in the hub's request.</param>
/// <param name="TokenCheck"><c>enforced</c> or <c>off</c>. Null in the hub's request.</param>
/// <param name="InstanceId">
/// The instance's identifier: 64 lower-case hex digits, the same value a backup's manifest
/// records as its <c>instanceId</c>, so an archive can be matched to a running instance. It is
/// stored with the instance's data and never changes once stored. Null, which the wire leaves
/// out, when the instance does not know it; that is "not known", never a mismatch. Null in the
/// hub's request. An instance of a build before the field existed leaves it out as well.
/// </param>
public sealed record HubHello(string ContractVersion, IReadOnlyList<string> Operations, string? InstanceVersion = null, string? TokenCheck = null,
    string? InstanceId = null);

/// <summary>The mode and who set it.</summary>
/// <param name="Mode"><c>full</c>, <c>restricted</c> or <c>dr</c>.</param>
/// <param name="Source">
/// Who set it: <c>default</c> (nobody), <c>start</c> (the start rule), <c>hub</c>,
/// <c>administrator</c> (in the instance's console), or <c>unreadable</c> (the record could not
/// be read and the instance holds itself restricted).
/// </param>
/// <param name="SetBy">The administrator's username, or the operator name the hub gave.</param>
/// <param name="Reason">The reason given.</param>
/// <param name="SetAtUtc">When it was set.</param>
/// <param name="CrlsExpireFromUtc">
/// In DR mode only, which signs no new CRL: the earliest <c>nextUpdate</c> among the newest full
/// CRLs of the instance's enabled CAs. From then on a relying party that checks a CRL sees an
/// expired one, until the mode is changed. Left out in every other mode, and when no CRL has been
/// signed or the time could not be read.
/// </param>
public sealed record HubMode(string Mode, string Source, string? SetBy = null, string? Reason = null, DateTime? SetAtUtc = null,
    DateTime? CrlsExpireFromUtc = null);

/// <summary>The body of <c>PUT /hub/v1/mode</c>.</summary>
/// <param name="Mode"><c>full</c>, <c>restricted</c> or <c>dr</c>.</param>
/// <param name="Reason">Why; optional, recorded with the change.</param>
public sealed record HubSetModeRequest(string Mode, string? Reason = null);

/// <summary>Health as the instance sees it: the answer of <c>GET /hub/v1/health</c>.</summary>
/// <param name="Status"><c>healthy</c>, <c>degraded</c> or <c>unhealthy</c>.</param>
/// <param name="Mode">The mode and who set it.</param>
/// <param name="TokenCheck"><c>enforced</c>, or <c>off</c> while the instance holds no affiliation token hash.</param>
/// <param name="InstanceVersion">The instance's product version.</param>
/// <param name="ContractVersion">The instance's contract version.</param>
/// <param name="TimestampUtc">When the answer was made.</param>
/// <param name="Checks">The instance's own readiness checks, as <c>/health/ready</c> reports them. Their shape is the instance's and may grow.</param>
public sealed record HubHealth(
    string Status,
    HubMode Mode,
    string TokenCheck,
    string InstanceVersion,
    string ContractVersion,
    DateTime TimestampUtc,
    JsonElement? Checks = null);

/// <summary>The answer of <c>POST /hub/v1/backup</c>.</summary>
/// <param name="FileName">The archive's file name, in the instance's backup directory.</param>
/// <param name="SizeBytes">The archive's size.</param>
/// <param name="CreatedAtUtc">When it was completed.</param>
public sealed record HubBackupResult(string FileName, long SizeBytes, DateTime CreatedAtUtc);

/// <summary>The body of <c>PUT /hub/v1/affiliation-token</c>. The request is authorised by the old token.</summary>
/// <param name="NewTokenSha256">The SHA-256 of the new token's UTF-8 bytes, as 64 hex digits.</param>
public sealed record HubReplaceTokenRequest(string NewTokenSha256);

/// <summary>The answer of <c>PUT /hub/v1/affiliation-token</c>.</summary>
/// <param name="TokenCheck">Always <c>enforced</c> afterwards.</param>
public sealed record HubReplaceTokenResult(string TokenCheck);

/// <summary>The body of every refusal and failure.</summary>
/// <param name="Error">A code from <see cref="HubLocalContract.Errors"/>.</param>
/// <param name="Message">What happened, for a person.</param>
/// <param name="ContractVersion">The instance's contract version.</param>
/// <param name="Operations">The operations the instance has; sent with <c>operation_not_listed</c> and <c>contract_version_unsupported</c>.</param>
public sealed record HubError(string Error, string Message, string ContractVersion, IReadOnlyList<string>? Operations = null);

/// <summary>
/// The answer of <c>GET /hub/v1/inventory</c> (since contract 1.1): what the instance already
/// knows about itself, read and not worked out for the request. It carries no issued
/// certificate, user, key, secret or audit entry, and neither health nor the mode. Unlike the
/// other answers, a field with nothing to say is sent as <c>null</c> and not left out.
/// </summary>
/// <param name="InstanceVersion">The instance's product version.</param>
/// <param name="Schema">The migrations applied to the instance's databases.</param>
/// <param name="Signer">The signer as the instance last saw it; null when it has not asked the signer since this process started.</param>
/// <param name="WebTlsCertificate">The certificate the instance's HTTPS listener serves; null when none is loaded.</param>
/// <param name="NewestBackup">The newest backup archive in the instance's backup directory; null when there is none or the directory cannot be read.</param>
/// <param name="FailingJobs">Every scheduled job whose last run failed or timed out; empty when none did.</param>
/// <param name="CertificateAuthorities">Every X.509 CA that is not deleted. SSH CAs are not listed.</param>
public sealed record HubInventory(
    string InstanceVersion,
    HubInventorySchema Schema,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventorySigner? Signer,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventoryWebTlsCertificate? WebTlsCertificate,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventoryBackup? NewestBackup,
    IReadOnlyList<HubInventoryFailingJob> FailingJobs,
    IReadOnlyList<HubInventoryCertificateAuthority> CertificateAuthorities);

/// <summary>The schema version of the instance: the migrations applied to each of its databases.</summary>
/// <param name="Application">The application database; null when its migration history could not be read.</param>
/// <param name="Audit">The audit database; null when the instance has none of its own or its migration history could not be read.</param>
public sealed record HubInventorySchema(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventoryMigrations? Application,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventoryMigrations? Audit);

/// <summary>The migrations applied to one database.</summary>
/// <param name="NewestMigration">The id of the newest applied migration; null when none is applied.</param>
/// <param name="AppliedCount">How many migrations are applied.</param>
public sealed record HubInventoryMigrations(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? NewestMigration,
    int AppliedCount);

/// <summary>The signer's state as the instance knew it the last time its own health check asked the signer.</summary>
/// <param name="State">
/// <c>unlocked</c> (it holds its keys and can sign), <c>locked</c> (it answered and its keystore
/// is not open), or <c>unreachable</c> (it did not answer).
/// </param>
/// <param name="CheckedAtUtc">When the instance asked. The state is as old as this.</param>
public sealed record HubInventorySigner(string State, DateTime CheckedAtUtc)
{
    /// <summary><see cref="State"/>: the signer holds its keys and can sign.</summary>
    public const string Unlocked = "unlocked";
    /// <summary><see cref="State"/>: the signer answered and its keystore is not open.</summary>
    public const string Locked = "locked";
    /// <summary><see cref="State"/>: the signer did not answer.</summary>
    public const string Unreachable = "unreachable";
}

/// <summary>The certificate the instance's own HTTPS listener serves.</summary>
/// <param name="ExpiresAtUtc">Its notAfter.</param>
public sealed record HubInventoryWebTlsCertificate(DateTime ExpiresAtUtc);

/// <summary>The newest backup archive in the instance's backup directory.</summary>
/// <param name="FileName">The archive's file name.</param>
/// <param name="CreatedAtUtc">When the file was created.</param>
/// <param name="AgeSeconds">How old it was when the answer was made, in whole seconds.</param>
/// <param name="Valid">
/// What the last run of the backup verification job found for this archive: true when it passed
/// the checks, false when it failed them. Null when that job has not checked this archive: it has
/// never run, or the archive is newer than its last run. Never the result of a check made for
/// this request.
/// </param>
/// <param name="VerifiedAtUtc">When that run of the verification job checked this archive; null exactly when <paramref name="Valid"/> is null.</param>
public sealed record HubInventoryBackup(
    string FileName,
    DateTime CreatedAtUtc,
    long AgeSeconds,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] bool? Valid,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] DateTime? VerifiedAtUtc);

/// <summary>
/// A scheduled job whose last run failed or timed out. The error itself is not sent: it is the
/// text of an exception, which can name a host, a directory entry or an account, and a hub never
/// sees an instance's data. The reason is on the instance's own Schedules page.
/// </summary>
/// <param name="Name">The job's name, as the console's Schedules page shows it; a per-row job is <c>Kind:id</c>.</param>
/// <param name="Kind">
/// The kind of job, without the id of the row it ran for: <c>CrlExport</c> for
/// <c>CrlExport:&lt;id&gt;</c>, and the name itself for a job that runs once for the instance. A
/// hub shows this; the id means something only inside the instance.
/// </param>
/// <param name="LastRunUtc">When that run was; null when the scheduler recorded no time.</param>
public sealed record HubInventoryFailingJob(
    string Name,
    string Kind,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] DateTime? LastRunUtc);

/// <summary>One X.509 certificate authority of the instance.</summary>
/// <param name="Name">The CA's name.</param>
/// <param name="Label">The CA's label, the segment of its URLs; null when it has none.</param>
/// <param name="State"><c>active</c> or <c>disabled</c>. A deleted CA is not listed.</param>
/// <param name="CertificateExpiresAtUtc">The notAfter of the CA's certificate; null when the CA has no certificate on record.</param>
/// <param name="Crl">The newest full CRL of the CA; null when none has been signed.</param>
/// <param name="OcspResponderCertificateExpiresAtUtc">The notAfter of the CA's delegated OCSP responder certificate; null when it has none.</param>
public sealed record HubInventoryCertificateAuthority(
    string Name,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Label,
    string State,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] DateTime? CertificateExpiresAtUtc,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] HubInventoryCrl? Crl,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] DateTime? OcspResponderCertificateExpiresAtUtc)
{
    /// <summary><see cref="State"/>: the CA is enabled.</summary>
    public const string Active = "active";
    /// <summary><see cref="State"/>: the CA is disabled.</summary>
    public const string Disabled = "disabled";
}

/// <summary>The newest full CRL of a CA, as already signed and stored.</summary>
/// <param name="Number">Its CRL number.</param>
/// <param name="NextUpdateUtc">Its nextUpdate: when the next CRL is due at the latest.</param>
public sealed record HubInventoryCrl(long Number, DateTime NextUpdateUtc);

/// <summary>
/// The body of <c>POST /hub/v1/backup/prune</c>. At least one of the two is given; with both, an
/// archive is deleted when either selects it. The newest archive is never deleted, and neither is
/// one younger than the instance's own floor, <c>Backup.MinimumRetentionDays</c>.
/// </summary>
/// <param name="Keep">How many of the newest archives to keep: 1 to 10000.</param>
/// <param name="MaxAgeDays">Archives created more than this many days ago are deleted: 1 to 36500.</param>
public sealed record HubPruneBackupsRequest(int? Keep = null, int? MaxAgeDays = null)
{
    /// <summary>The largest <see cref="Keep"/> accepted.</summary>
    public const int MaxKeep = 10_000;

    /// <summary>The largest <see cref="MaxAgeDays"/> accepted.</summary>
    public const int MaxMaxAgeDays = 36_500;
}

/// <summary>One backup archive in the instance's backup directory.</summary>
/// <param name="FileName">The archive's file name.</param>
/// <param name="SizeBytes">The archive's size.</param>
/// <param name="CreatedAtUtc">When the file was created.</param>
public sealed record HubBackupFile(string FileName, long SizeBytes, DateTime CreatedAtUtc);

/// <summary>The answer of <c>POST /hub/v1/backup/prune</c>.</summary>
/// <param name="Deleted">The archives deleted, newest first.</param>
/// <param name="Remaining">The archives still in the backup directory, newest first.</param>
/// <param name="KeptByMinimumRetention">The file names of archives the request selected that the instance's <c>Backup.MinimumRetentionDays</c> kept; they are among <paramref name="Remaining"/>.</param>
/// <param name="NotDeleted">The file names of archives the request selected that could not be deleted; they are among <paramref name="Remaining"/>, and the instance's log has the cause.</param>
public sealed record HubPruneBackupsResult(
    IReadOnlyList<HubBackupFile> Deleted,
    IReadOnlyList<HubBackupFile> Remaining,
    IReadOnlyList<string> KeptByMinimumRetention,
    IReadOnlyList<string> NotDeleted);
