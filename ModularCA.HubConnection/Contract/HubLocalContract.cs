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
    public const string Version = "1.0";

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

        /// <summary>Every operation of this version.</summary>
        public static IReadOnlyList<string> All { get; } = [Hello, HealthRead, ModeRead, ModeSet, BackupCreate, AffiliationTokenReplace];
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
public sealed record HubHello(string ContractVersion, IReadOnlyList<string> Operations, string? InstanceVersion = null, string? TokenCheck = null);

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
public sealed record HubMode(string Mode, string Source, string? SetBy = null, string? Reason = null, DateTime? SetAtUtc = null);

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
