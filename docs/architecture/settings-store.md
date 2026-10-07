# Settings store

Status: design from 2026-10-05, with the owner's decisions since. Building started 2026-10-06 for
0.4.1; "Built so far" under section 10 says what exists.

## Why

`config/config.yaml` holds 37 sections and about 220 settings. It is read once at startup into
the `SystemConfig` singleton. Thirty-three call sites in six classes change that singleton in
place and rewrite the file through `ConfigYamlWriter`. That worked for one host. It does not work
for what ModularCA now is.

- **A console change reaches one host.** The admin API is the control role's. On a split install
  each host has its own `config.yaml`, so a change to ACME policy, the certificate policy, the
  integration API key, network audit or the IP whitelist exemptions changes the control host's
  memory and file. The enrollment and validation hosts that enforce those settings never see it.
- **"Live" is an accident of reference sharing.** Some consumers re-read the singleton on every
  call and see a change at once. Others copied a value in their constructor and keep it until
  restart: `IpWhitelistMiddleware`, `JwtIpBindingMiddleware`, `MtlsMiddleware`,
  `RequestAuditMiddleware`, `PlainHttpBodyLimitMiddleware` and `SiemLogFormatter`. Some settings
  are half-live. `JwtTokenService` signs with the live `JWT.Secret` and embeds the live
  `BindJwtToIp`, but bearer validation and the binding middleware keep the startup values.
- **The file is an unaudited, unversioned edit path.** Anyone who can write the file changes
  authentication, audit and network trust at the next restart, and nothing records who did it or
  what the value was before. The audit row a console change writes carries part of the request
  body, not a before/after diff.
- **Secrets sit in the file in the clear.** That includes the JWT secret, the LDAP bind password,
  the SMTP password and OAuth2 secret, and both integration API keys. A backup archive carries
  that file inside the archive encryption, while the Data Protection ring next to it travels
  wrapped by the signer.
- **There is no history, no conflict detection and no approval.** Two admins saving the same
  card overwrite each other. Every settings change is gated by step-up alone, whatever it weakens.

The owner's goals are **live reload**, and **settings that are hard to change outside the API**:
audited, versioned, with step-up and approvals where needed. HA is a warm standby on PostgreSQL
streaming replication, so anything in the database reaches the standby for free.

## Decisions in one place

- Every `SystemConfig` property gets one of five classes (below). Only *instance-wide* settings
  and *secrets* move to the database. Bootstrap, host-local and signer-local settings stay in
  files.
- Storage is **one row per setting**, for the settings that were set, under a key that is the
  property path joined by underscores (`Acme_Http01_MaxAddresses`). The value is JSON of the
  setting's type. A global revision number orders every change. History is append-only, and
  every change is audited before it commits.
- Secrets live in a separate table. Secrets the node has to *use* are wrapped by the signer, as
  `signer-hardening.md` (in progress) specifies. API keys, which the node only has to *verify*,
  are stored as hashes.
- Reload uses PostgreSQL `LISTEN/NOTIFY`, with a 30-second poll as a backstop. Each process holds
  an immutable snapshot at a revision and swaps it whole. Consumers move from the singleton to
  per-section `IOptionsMonitor<T>`, fed by a custom options source. A custom
  `IConfigurationProvider` is not used.
- Every property declares how it reloads: live, component, or restart. Each node reports the
  revision it has applied and the restart-class changes it has not, and the console shows both.
- Precedence, highest first: command line, environment, database, host-local file, built-in
  defaults. Environment values still win, and they show as "set by environment" and cannot be
  edited.
- Break-glass is a **command-line tool**, `--settings`, run on the host. It writes through the
  same store, with history and an audit record. No file override is honoured.
- The control role imports `config.yaml` at its first start after the upgrade, then rewrites
  the file to host-local keys only. Other hosts compare their files with the store, and a host
  whose file disagrees refuses to start until the operator decides.
- Changes that weaken a security setting can require a ceremony. Changes that tighten it never
  do.

## Owner decisions (2026-10-05)

- **The JWT secret is stored in the database, wrapped by the signer.** A control or enrollment
  process needs the signer reachable to start serving sign-in; until then sign-in answers 503.
  `MODULARCA__JWT__SECRET` remains an escape hatch.
- **Environment variables may override instance-wide settings.** The console shows them as "set
  by environment", they cannot be edited there, and a change of value is audited.
- The other open questions in section 11 are still open.

## Owner decisions (2026-10-06)

- **One row per setting, named with underscores.** "Items can be split with underscores", for
  example `Acme_Http01_MaxAddresses`. Section 2 is rewritten for it. The database connection is
  not among them: a setting needed to reach the database cannot live in it.

## 1. Classification

| Class | Meaning | Lives in |
|---|---|---|
| **a. Bootstrap** | Needed before the database can be reached | `db.yaml` (and `setup-database.yaml` in setup mode), `config.yaml` |
| **b. Signer-local** | Read by the signer role only | `signer.yaml` in the signer's own directory, named by `--signer-dir` in the root-owned unit (being built; `SignerPaths`) |
| **c. Host-local** | Differs per host by nature: listeners, files, paths, network position | `config.yaml` on that host |
| **d. Instance-wide** | One value for the whole instance, every role on every host | database |
| **e. Secret** | Instance-wide and secret | database, wrapped (or hashed) |

Counts, by leaf property, with each list element type counted once:

| Class | Properties | Sections touched |
|---|---|---|
| a. Bootstrap | 15 | DB, Schema |
| b. Signer-local | 11 | Hsm, Signer (signer side) |
| c. Host-local | 47 | Roles, Signer (node side), Ingress, Redis, SshCa, PolicySync, Https, Http, Logging, Security, Mtls, Backup, Audit |
| d. Instance-wide | 142 | 28 sections |
| e. Secret | 8 | JWT, LdapAuth, Email, Webhook, IntegrationApi, CertManager |
| **Total** | **223** | 37 sections |

Nine sections stay in files entirely: DB, Schema, Roles, Hsm, Signer, Ingress, Redis, SshCa and
PolicySync. Twenty-eight have instance-wide content. Seven of those (Security, Logging, Http,
Https, Mtls, Backup, Audit) also keep some host-local properties in the file under the same
section name, so the API keeps its section shape.

Some secrets stay in files, because their class decides where they live, not their secrecy:
`DB.*.Password` (a), `Https.CertificatePassword` and `Signer.ClientCertificatePassword` (c), and
`Hsm.Pin`, `Signer.ServerCertificatePassword` and `Signer.IdentityCaPassword` (b).

"Reload today" describes the host that served the PUT. Other hosts reload nothing until their own
file is edited and they restart. **Live** means the next call sees the new value. **Component**
means one component rebuilds itself. **Restart** means the process must restart.

| Setting | Class | Read by | Reload today | Reload after |
|---|---|---|---|---|
| `DB.App.*`, `DB.Audit.*` (Host, Port, Username, Password, Database, SslMode) | a | connection strings in `StartModularCA`, schema check, `--unlock-user`, `--upgrade-check`, `--db-ownership`, `BackupRestore`, `Unlocker`, `KeystoreDbPassphraseLoader` | restart | restart |
| `Schema.WaitSeconds`, `MigrationCommandTimeoutSeconds`, `MigrationLockTimeoutSeconds` | a | `SchemaStartup`, `SignerRole`, `UpgradeCheckCommand` | restart | restart |
| `Roles` | c | `ProcessRoles.Parse`; `--role` wins | restart | restart |
| `Signer.Mode`, `Endpoint`, `ClientCertificate`, `ClientCertificatePassword`, `PinnedServerSpki` | c | the node's `RemoteSigningService` | restart | restart |
| `Signer.Listen`, `ServerCertificate`, `ServerCertificatePassword`, `PinnedClientSpki`, `IdentityCa`, `IdentityCaPassword` | b | `SignerRole`, `SignerIdentityCommands` | restart | restart |
| `Hsm.Enabled`, `ModulePath`, `SlotId`, `Pin` | b | `SignerRole`; `StartModularCA` when the signer is in process | restart | restart |
| `Hsm.KeyMappings` | b | nothing | — | delete |
| `Ingress.Routes`, `HealthCheckIntervalSeconds`, `HealthCheckTimeoutSeconds`, `HealthCheckPath`, `UpstreamCaCertificatePath`, `DangerousAcceptAnyUpstreamCertificate` | c | `IngressHosting`, `UpstreamTrustPolicy` | restart | restart |
| `Redis.Enabled`, `ConnectionString`, `InstanceName` | c | distributed cache and Data Protection ring registration | restart | restart |
| `Https.Mode`, `ListenAddress`, `Port`, `CertificatePath`, `CertificatePassword` | c | Kestrel setup, `WebTlsProvisioningService`, `AdminWebTlsController`, `TlsRenewalJob` | restart (the certificate itself hot-reloads) | same |
| `Https.PendingSubjectDn`, `PendingSans`, `PendingValidityDays`, `PendingKeyAlgorithm`, `PendingKeySize` | c | `WebTlsProvisioningService`, as a bootstrap hand-off | first start | same |
| `Https.PublicDomain`, `PublicPort` | d | WebAuthn rpId and origin, SNI names for mTLS and EST, `PublicNameResolver`, `HttpsRedirectTarget`, ACME controllers and `AcmeJwsAttribute`, `MtlsController`, MSAE services, `CaCreationService` (default CDP/AIA base), public info and SSH controllers | split: live in URL builders, restart for WebAuthn and SNI | restart, declared |
| `Https.RenewalWindow`, `RenewalCheckSchedule` | d | `TlsRenewalJob`, scheduler registry | live | live |
| `Http.Port` | c | Kestrel, `PlainHttpBodyLimitMiddleware` (captured), `HttpSchemeEnforcementMiddleware`, ingress, `CaCreationService` URL fallback | restart | restart |
| `Http.PublicPort` | d | `CaCreationService` default CDP/AIA base | live | live |
| `Http.CorsOrigins`, `EnableCors` | d | `AddCors` at startup | restart | live (a CORS policy provider reads the monitor) |
| `Http.SwaggerEnabled` | d | pipeline built at startup | restart | restart |
| `Http.TrustedProxyCidrs`, `ForwardedHeaderHopLimit`, `Security.BehindReverseProxy` | c | forwarded-headers options; `LoginRateLimitMiddleware` reads `BehindReverseProxy` live | restart | restart |
| `Http.Hsts.MaxAgeSeconds`, `IncludeSubDomains`, `Preload` | d | `AddHsts` at startup; `SecurityHeadersMiddleware` per request | split | live (one reader, the middleware) |
| `JWT.Secret` | e | `AddJwtBearer` signing key (startup); `JwtTokenService` (live) | split: signing live, validation restart | live, through an issuer-key resolver that also accepts the previous key for one token lifetime |
| `JWT.ExpirationMinutes` | d | `JwtTokenService`, `AuthController` | live | live |
| `JWT.Issuer`, `Audience` | d | bearer validation (startup), `JwtTokenService` | split | live (the scheme's options cache is cleared on change) |
| `Security.BindJwtToIp` | d | `JwtTokenService` (live), `JwtIpBindingMiddleware` (captured) | split | live |
| `Security.BindRefreshTokenToIp`, `BindRefreshTokenToFingerprint`, `AllowRefreshTokenMismatch`, `EnforceRefreshTokenPoP` | d | `AuthController` refresh | live | live |
| `Security.MaxPerUsernameLoginFailures`, `PerUsernameLoginFailureWindowMinutes` | d | `LoginRateLimitMiddleware` | live | live |
| `Tokens.RefreshTokenDays` | d | `JwtTokenService` | live | live |
| `LdapAuth.Enabled`, `Host`, `Port`, `UseSsl`, `RequireTls`, `SearchBaseDn`, `SearchFilter`, `BindDn`, `GroupSyncSchedule`, `GroupSyncEnabled`, `AutoProvisionUsers`, `GroupSearchBaseDn`, `GroupSearchFilter`, `GroupMemberAttribute`, `GroupToRoleMappings` | d | `LdapAuthService`, `AuthController`, `ProtocolCredentialService`, `LdapGroupSyncService`, `LdapGroupSyncJob`, registry, startup mapping check | live | live |
| `LdapAuth.BindPassword` | e | `LdapAuthService`, `LdapGroupSyncService` | live | live |
| `Logging.MinLevel` | d | `LoggingLevelSwitch` | live, on the control host only | live, on every node |
| `Logging.FilePath`, `RetentionDays`, `MaxFileSizeMb`, `ConsoleFormat`, `VerboseErrors` | c | Serilog setup | restart | restart |
| `Logging.Syslog.Host`, `Port`, `Protocol`, `AppName`, `Facility` | d | Serilog sink at startup, gated by the `Syslog.Enabled` flag | restart | component (the sink sits behind a swappable wrapper) |
| `Logging.EventLog.Source`, `LogName` | c | Serilog sink, on Windows | restart | restart |
| `Logging.Network.Enabled`, `Host`, `Port`, `Protocol` | d | `SiemLogFormatter`, which captures the sub-object | live in place, stale once sections are swapped | live |
| `Scheduler.LeaseTtlSeconds`, `MissedRunPolicy`, `JobTimeouts`, `DefaultJobTimeoutSeconds`, `ConsecutiveFailureAlertThreshold` | d | `SchedulerService`, `SchedulerJobRunner`, `SchedulerJobRegistry`, `SingletonCronJob` | live (`MissedRunPolicy` at scheduler start) | live |
| `Metrics.Path` | d | `MapGet` at startup | restart | restart |
| `Email.Enabled`, `SmtpHost`, `SmtpPort`, `UseTls`, `AuthMethod`, `Username`, `OAuth2ClientId`, `OAuth2TokenUrl`, `OAuth2Scopes`, `FromAddress`, `FromName`, `AdminRecipients` | d | `EmailService`, `NotificationService`, `CertExpiryNotificationJob`, `AdminNotificationController` | live | live |
| `Email.Password`, `OAuth2AccessToken`, `OAuth2ClientSecret` | e | `EmailService` | live | live |
| `IpWhitelist.Enabled` | d | `IpWhitelistMiddleware` (captured) | restart | live |
| `IpWhitelist.ExemptPaths` | d | `IpWhitelistMiddleware` | live | live |
| `NetworkAudit.Enabled`, `LogAllRequests`, `ExcludePaths` | d | `RequestAuditMiddleware` (captured) | restart | live |
| `Webhook.Enabled`, `MaxRetries`, `RetryDelaySeconds`, `Endpoints[].Url`, `Endpoints[].Events` | d | `WebhookService` | live | live |
| `Webhook.Endpoints[].Secret` | e | `WebhookService` | live | live |
| `Mtls.Enabled`, `AuthSubdomain` | d | Kestrel SNI callback, `MtlsController`, `MtlsMiddleware` | restart | restart |
| `Mtls.RequiredPaths` | d | `MtlsMiddleware` (captured) | restart | live |
| `Mtls.TrustedCaCertPaths` | c | Kestrel client-certificate anchors, `MtlsMiddleware` | restart | restart |
| `Acme.CleanupSchedule`, `ExternalAccountRequired`, `TermsOfServiceUrl`, `EnforceCaa`, `NonceLifetimeSeconds`, `Http01.MaxAddresses`, `Http01.TimeoutSeconds`, `ChallengeProcessingTimeoutMinutes`, `ChallengeMaxAttempts` | d | ACME controllers, `AcmeNonceService`, `AcmeChallengeService`, `CaaCheckService`, `AcmeCleanupJob` | live | live |
| `Est.AuthSubdomain` | d | Kestrel SNI callback | restart | restart |
| `Est.TrustAnchorRefreshSeconds` | d | `EstTrustAnchorCache` (captured) | restart | live |
| `ProtocolCleanup.Schedule`, `OrphanRequestGraceMinutes` | d | `ProtocolCleanupJob` | live | live |
| `Backup.Enabled`, `RetentionCount`, `Schedule`, `MaxBackupAgeDays`, `VerifyOnSchedule`, `CreateOnSchedule`, `VerifyCount`, `MinimumRetentionDays` | d | backup creation and verification jobs, registry, `AdminBackupController` | live | live |
| `Backup.OutputPath`, `EncryptionKeyPath`, `EncryptionMode`, `PasswordFilePath` | c | backup jobs, `BackupRestore`, the backup static-file mapping at startup | live; restart for the mapping | same |
| `WebAuthn.Enabled`, `RelyingPartyName` | d | `AddFido2` at startup, `AuthController` | restart | restart |
| `WebAuthn.EnforceForGroups` | d | `AuthController` | live | live |
| `Alert.Enabled`, `MinimumSeverity`, `CooldownMinutes` | d | `SecurityAlertService` | live | live |
| `CertExpiryNotification.Enabled`, `WarningDaysBeforeExpiry`, `Schedule` | d | `CertExpiryNotificationJob`, registry | live | live |
| `ComplianceScan.Enabled`, `Schedule`, `MinRsaKeySize`, `DeprecatedAlgorithms`, `WarnOverValidityDays`, `ExpiringWithinDays` | d | `ComplianceScanJob`, `CertHealthScoreService` | live | live |
| `CertPolicy.Enabled`, `MinRsaKeySize`, `ForbiddenAlgorithms`, `RequireSans`, `AlgorithmSunsetRules`, `ExpireCheckSchedule` | d | `CertPolicyService` (issuance, enrollment role), `CertExpireJob` | live | live |
| `CertPolicy.RsaSignaturePadding` | d | the static `KeyAlgorithmPolicy.UseRsaPss`, set once at startup | restart | live |
| `AutoRenewal.Enabled`, `Schedule`, `RenewDaysBeforeExpiry`, `AutoApprove`, `RequireKeyRotation` | d | `AutoRenewalJob`, `AdminCertificateController` | live | live |
| `IntegrationApi.Enabled`, `SpaceId` | d | `ApiKeyAuthAttribute`, `InfraController`, `IntegrationScopeCheck`, `--upgrade-check` | live (the console says restart) | live |
| `IntegrationApi.ApiKey` | e, hashed | `ApiKeyAuthAttribute` | live | live |
| `CertManager.Enabled`, `DefaultCertProfileId`, `DefaultSigningProfileId`, `SpaceId` | d | `CertManagerApiKeyFilter`, `CertManagerController`, `IntegrationScopeCheck` | live (the console says restart) | live |
| `CertManager.ApiKey` | e, hashed | `CertManagerApiKeyFilter` | live | live |
| `PolicySync.Enabled`, `PolicyDirectory`, `SyncOnStartup` | c | startup sync, `AdminPolicySyncController` | startup | startup; removed from the admin API |
| `SshCa.SshKeygenPath`, `KeyStoragePath` | c | `SshCaService`, `BackupRestore` | live | live; removed from the admin API |
| `SourceCode.Url`, `License` | d | `PublicInfoController` | live | live |
| `Audit.Retention.Enabled`, `GeneralRetentionDays`, `NetworkRetentionDays`, `ArchiveBeforeDelete`, `Schedule`, `DeleteBatchSize` | d | `AuditRetentionJob`, registry | live | live |
| `Audit.Retention.ArchivePath` | c | `AuditRetentionJob` | live | live |
| `Audit.FailMode`, `FailureAlertCooldownSeconds` | d | `AuditService`, `AuditFailClosedMiddleware` | live | live |

One more instance-wide setting lives outside `SystemConfig` and is not counted above. `Msae`
(`TemplateOidArc`, `MoveGeneratedTemplateOids`) is bound from `IConfiguration`, which means
`appsettings.json` and the environment. The template OID arc has to be the same on every node, so
it joins the store as a section.

Whether the install is configured is not a property. It is the presence of `config.yaml` and
`db.yaml`, read by `StartModularCA`, `SetupRedirectMiddleware`, `IpWhitelistMiddleware` and the
container entrypoint. After bootstrap `config.yaml` therefore always exists, even when every
host-local key in it holds the default.

### The judgement calls

- **The public name is instance-wide.** `Https.PublicDomain` and the two public ports are baked
  into what the instance publishes: CDP and AIA defaults in CA rows, ACME URLs and JWS binding,
  and the WebAuthn rpId. A promoted standby that answers under another name breaks every passkey
  and every published URL. A member's own extra names are a different thing (open question 1).
- **The JWT secret is a wrapped secret, not a host file.** One key per instance lets a standby
  validate the access tokens the primary issued, and lets the key be rotated with a key id. The
  cost is that a control process needs the signer to unwrap it at start (section 3). Refresh
  tokens are database rows, so a per-host key would have cost only one refresh at failover. That
  makes this a close call (open question 2).
- **Network position is host-local.** `TrustedProxyCidrs`, `ForwardedHeaderHopLimit` and
  `BehindReverseProxy` describe what sits in front of *this* host. A different value on the
  ingress host and on a node is correct, not drift.
- **Paths are host-local, and two of them leave the API.** `SshCa.SshKeygenPath` lets a holder of
  config rights choose the binary the node executes. `ssh-keystore.md` found that and called it
  code execution one step removed. `PolicySync.PolicyDirectory` lets them point the server at a
  directory of YAML that rewrites profiles. Both become host-local and read-only in the console,
  so changing them needs the host.
- **`Backup.EncryptionMode` is host-local.** It names which key file on this host encrypts
  archives (`backup.key` or `backup-password.key`). Those files are host-local and deny-listed from
  archives, so the mode goes with them.
- **Logging is split.** The level and the SIEM and syslog targets are instance-wide. File paths,
  retention, console format and verbose errors describe one host's disk and supervisor.
- **Redis is topology.** Every node must name the same Redis, just as every node names the same
  database. A wrong value moves the Data Protection ring and makes every protected column
  unreadable. That is a migration, not a setting, so it stays in the file next to `db.yaml`.

### Classification in code

Each leaf property carries `[Setting(SettingClass.X, SettingReload.Y)]`, and a secret says how it
is kept (`Secret = SettingSecretKind.Wrapped` or `Hashed`). `SettingsCatalog` builds the list of
settings from those attributes and refuses to build when a leaf has none, so the test that builds
it fails on an undeclared setting, the same way the `NodeRole` convention test fails on an
undeclared controller. The reload mode is the one in the "Reload after" column: what the setting
does once its reader takes it from the store. The catalog is also what the console and the docs
will list settings from, so they cannot drift from the code.

A list or a dictionary is one setting. The element types (`WebhookEndpoint`, `IngressRouteConfig`,
`HsmKeyMapping`) declare nothing, so the catalog holds 216 settings where the table above counts
223 properties. `Backup.DatabaseTimeoutMinutes`, added after the table was drawn, is
instance-wide and live.

## 2. Storage model

### One row per setting

One row per setting **that has been set**, under a key made of the property path joined by
underscores: `Acme.Http01.MaxAddresses` is stored as `Acme_Http01_MaxAddresses`. The value is the
JSON of the setting's own type. A setting nobody has set has no row, and its default comes from
the C# type.

The draft proposed one JSON document per section and argued against rows. The owner chose rows
with underscore-separated names (2026-10-06). Each objection the draft raised has an answer in
the row model:

| Objection to rows | Answer |
|---|---|
| No types | The value is JSON, checked against the property's CLR type at write (`SettingsCatalog.Problem`) and again at load. |
| Awkward lists and dictionaries | A list or a dictionary is one setting and one row, stored whole (`IpWhitelist_ExemptPaths`, `Scheduler_JobTimeouts`). It replaces the default and is never merged into it. |
| A multi-key change has to stay atomic | One write sets any number of settings in one transaction under one revision. A reader sees all of the change or none. |
| History is a scatter of rows | History is one row per changed setting, grouped by the write's revision. A diff is the rows of a revision, and "who last changed this setting" is a lookup by key. |

Rows also give what a document could not: a version and a last-changed-by per setting, so two
admins changing different settings on one card do not conflict, and a key that maps one to one
onto the environment variable that overrides it (`MODULARCA__ACME__HTTP01__MAXADDRESSES`).

Sparse storage matters. A default that a new build changes reaches every install that never set
the value, as it does with YAML today. The console can show "default" as a source, and the history
shows what someone chose rather than a wall of defaults. Clearing a setting keeps its row with a
null value, so its version keeps counting; the setting is back on its default.

One value has one stored spelling: through the setting's type and back, with the members of
every object in name order. "The same value again" is then a text comparison and changes nothing.

The sections below were written for the document model and describe stages that are not built.
Where they say a section's document, read the rows of that section's settings: the API still
takes and returns a section, the import still writes one revision per section, and a ceremony
still carries one section's proposed values.

### Tables

```
"Settings"            Key varchar(200) PK, ValueJson text null, Version int, Revision bigint,
                      UpdatedAt timestamptz, ActorId uuid null, ActorName text, Source text
"SettingsHistory"     Id bigint PK, Revision bigint, Key varchar(200), Version int,
                      ValueJson text null, PreviousValueJson text null, ChangedAt timestamptz,
                      ActorId uuid null, ActorName text, Source text, Reason text null;
                      UNIQUE (Key, Version); INDEX (Revision)
"SettingsState"       Id int PK (always 1), Revision bigint
"SettingsSecrets"     Key varchar(200) PK, Kind text ('wrapped' | 'hash'), Value bytea null,
                      Version int, Revision bigint, UpdatedAt timestamptz,
                      ActorId uuid null, ActorName text, Source text
```

`SettingsHistory` also has `SecretDigest varchar(64) null`. These four exist (migration
`SettingsStore`). Still to come, with the stage that needs each:

```
"SettingsNodes"       NodeId text PK, Host text, Roles text, Build text, StartedRevision bigint,
                      AppliedRevision bigint, PendingRestart jsonb, EnvKeys text[],
                      Problems jsonb, LastSeenAt timestamptz
"SettingsImports"     Id uuid PK, Host text, FileHash bytea, KeyHashes jsonb,
                      ImportedAt timestamptz, Revision bigint
```

- Values are `text` holding JSON, as every other JSON column in the schema is. Nothing queries
  inside a value.
- `Version` counts per setting and is what a writer names to detect a concurrent change.
  `Revision` is one number across all settings, so a node's state is a single number.
- `SettingsState` is one row whose `Revision` is a concurrency token. A write raises it in the
  same save as its changes, so two writes cannot take the same revision: the second fails whole,
  reads again and retries. This replaces the sequence the draft proposed; it needs no raw SQL
  and no explicit lock.
- `Source` is `Api`, `Import`, `Cli`, `Bootstrap`, `Rollback`, `Ceremony`, `Restore` or `Upgrade`.
- History is append-only. A rollback is a new revision whose values are old ones.
- Which changed settings need a restart is read from the catalog by key, not stored.
- A secret never appears in `Settings` or `SettingsHistory`. History records that a secret
  changed, with the SHA-256 of what was stored for it (`SecretDigest`): the **wrapped** blob,
  or the stored hash. A hash of the plaintext would turn the history into a guessing oracle,
  the reason `signer-separation.md` gives for hashing the wrapped blob in the signer's audit.
  The audit record carries less still: the key and "set", "replaced" or "cleared".
- The key that wrapped a blob is named in the blob's own header, so the table has no column
  for it.
- `Webhook_Endpoints` is one setting whose elements each carry a secret. The whole list is kept
  as one wrapped secret; splitting it into a readable list and per-element secrets is not worth
  the bookkeeping.

### Secrets

| Kind | Settings | Stored as |
|---|---|---|
| Used by the node | `JWT.Secret`, `LdapAuth.BindPassword`, `Email.Password`, `Email.OAuth2AccessToken`, `Email.OAuth2ClientSecret`, `Webhook.Endpoints[].Secret` | wrapped by the signer under a new `SecretKind.SettingSecret`. Format, key choice, rotation, audit and the HSM fallback are as specified in `signer-hardening.md`, and not repeated here. |
| Verified by the node | `IntegrationApi.ApiKey`, `CertManager.ApiKey` | SHA-256 of the key. The keys are high-entropy bearer values. A hash needs no signer round trip and cannot be read back, which is right for a credential the admin sets and the client presents. |

When a secret comes from the environment, the store holds nothing for it. The node uses the
environment value, and an environment API key is hashed in memory at load.

As built:

- **A secret is written like any setting**, by its value, through `ISettingsStore.WriteAsync`.
  The store wraps or hashes it before anything is stored. The value is in no row, no history
  entry, no audit record and no refusal message.
- **A wrapped secret is bound to its key.** The store asks the signer to wrap it for
  `setting:<key>` (`setting:JWT_Secret`), and the signer returns a version 2 envelope that
  unwraps only for that name (`signer-hardening.md`, "The wrap: envelope v2"). A blob copied to
  another setting's row is refused there.
- **When the signer will not wrap, the write is refused whole.** Nothing is held in the clear
  to be wrapped later, and the other settings in the same write are not saved either.
- **Setting a wrapped secret again always replaces it**, even with the same value: two wraps of
  one value differ, so the stored blob cannot say whether the value changed.
- **A hashed secret is SHA-256 of the key**, and only of a key of at least 32 characters. A
  plain hash protects nothing that can be guessed, so a shorter key is refused. This is new:
  `config.yaml` accepts any API key today. The import has to decide what it does with an
  existing shorter key (open question 11).
- **Reading back**: `ISettingsStore.ApplySecretsAsync` unwraps each wrapped secret onto a
  `SystemConfig` and reports the ones it could not. A hashed secret is never set on the
  configuration; a presented key is checked with `SettingsSnapshot.HashedSecretMatches`.

### Renamed and reshaped settings

A rename is a pair of keys, old and new, registered the way `YamlConfigLoader.RenamedKeys` is;
a reshape is a function from the old value to the new. The control role applies them once at
start, as a revision with source `Upgrade`. An unknown key is refused at write and ignored with
a warning at read (`SettingsSnapshot.ApplyTo` reports it).

### Write path and concurrency

```
read SettingsState and the Settings rows the write names
an expected version given and the row differs   -> 409, current version and a diff
apply the change policy (below)                 -> 403, or 202 with a ceremony
check each value's type; validate the section with the change applied   -> 400
drop settings whose value would not change; nothing left -> done, no revision
revision = SettingsState.Revision + 1
append the audit row: revision, each changed key with before and after
  (secrets as "changed"), source, reason, ceremony
save in one transaction: the Settings rows, one SettingsHistory row per changed
  key, SettingsState raised to the revision; pg_notify('modularca_settings', revision)
on a save lost to another writer: append ConfigUpdateAborted naming the revision,
  read again and retry
```

The audit row is written **before** the save, so `Audit.FailMode=FailClosed` holds: no change
without its record. The cost is an occasional "aborted" row. The existing PUT endpoints name no
expected versions. A write of theirs changes only the settings whose value differs, so two
partial PUTs to one card no longer overwrite each other's fields, which they do today. The new
console sends the versions it read, as `If-Match`.

### Integrity: detect what cannot be prevented

The runtime role owns its tables (the 0.4.0 ownership model), and an owner can `UPDATE` anything,
so privileges cannot stop a direct edit. The store detects one instead. At load, a node checks
each row against the audit record of the revision that wrote it: the record carries the key and
the value after the change, in the canonical spelling the row stores, so the two are compared as
text. That audit row sits in the hash chain, so forging it means rewriting the chain. This needs
the row to name its audit record, which the store does not do yet (see "Built so far").

A mismatch raises a Critical `SettingsIntegrity` alert, and the node loads the newest value of
that setting in the history that does verify. If none verifies, it loads the default. If the audit database
cannot be reached at load, the node loads without verifying and says so in `/health/ready`.
Under `FailMode=FailClosed` it waits and retries instead, as for the schema check.

### Validation

Every rule moves into a per-section `ISettingsValidator<T>`. The same validator runs at the API,
in the CLI, at import and at load. The rules exist today, scattered:

- `ConfigInputRules`: CORS origins, mail recipient lists, warning days, algorithm sunset rules.
- `CronExpressionValidator`, which today runs at startup over five schedules and should cover
  every schedule.
- The controller bounds: ports from 1 to 65535, `RefreshTokenDays` up to
  `TokenConfig.MaxRefreshTokenDays`, `MinRsaKeySize` of at least 2048, `LeaseTtlSeconds` of at
  least 15, job timeouts from 1 to 86400, an absolute http(s) `TermsOfServiceUrl`, the console
  format enum.
- `LdapGroupSyncService.ValidateMappingsAsync`, the JWT secret's 64-byte minimum, and the mTLS
  anchor loadability check that `UpdateMtls` does.

One rule governs them: **anything that can stop a start also runs at write.** A value the store
accepted must never brick the next start. Load-time rules may be looser, as `CorsOriginsError`
already is with `requireBareOrigin: false`, so that an old value still loads.

The controller rules that are policy rather than syntax move too, into `ISettingsChangePolicy<T>`.
Then the generic section endpoint and the CLI cannot get around them:

- LDAP identity fields are super-only.
- Re-enter the bind or SMTP password when the server changes.
- The redaction sentinels `***` and `(env)` mean "unchanged".
- Clearing the mTLS lists raises an alert.

### Change policy: step-up, super, ceremony

| Tier | Sections | Gate |
|---|---|---|
| Routine | Logging (level and targets), Scheduler, Tokens, Metrics, Email (non-secret), Https renewal, Webhook retries, Acme (cleanup, nonce, http-01, challenge limits, terms URL), Est, ProtocolCleanup, Backup schedule and retention counts, CertExpiryNotification, ComplianceScan, SourceCode, Msae | step-up (`UpdateConfig`), as today |
| Security | JWT, Security, LdapAuth, Http (CORS, Swagger, HSTS), IpWhitelist, NetworkAudit, Mtls, WebAuthn, Audit, CertPolicy, `Acme.ExternalAccountRequired` and `EnforceCaa`, `AutoRenewal.AutoApprove` and `RequireKeyRotation`, `Backup.Enabled` and `MinimumRetentionDays`, Alert, IntegrationApi, CertManager, every secret | step-up always. A **weakening** change needs a `SettingsChange` ceremony when the instance requires settings ceremonies. The LDAP identity fields stay super-only. |

Each property in the security tier declares which direction weakens. Some examples:

- `IpWhitelist.Enabled` true to false.
- Any `Audit.Retention.*Days` decreased.
- `Audit.FailMode` moved away from `FailClosed`.
- `CertPolicy.MinRsaKeySize` decreased, or an entry removed from `ForbiddenAlgorithms`.
- An origin added to `Http.CorsOrigins`.
- `Http.SwaggerEnabled` turned on.
- `WebAuthn.EnforceForGroups` shortened.
- `Mtls.RequiredPaths` cleared.
- `NetworkAudit.Enabled` turned off.
- A new API key.

A change that tightens applies at once. This is the rule the space policy ceremony already
applies to `RequireKeyCeremony`: downgrades are gated, upgrades are not.

The ceremony is a new `CeremonyType.SettingsChange`, modelled on `InstancePolicyChange`:

- Its quorum is the instance's `CeremonyRequiredApprovals`, snapshotted at proposal.
- The initiator never counts.
- There is one pending ceremony per section.
- It carries the proposed document and the base version. It applies only if the section is
  still at that version, and fails as stale otherwise.

The switch is a new `SecurityPolicy.RequireSettingsCeremony`. It is off on upgrade, so behaviour
does not change. Turning it off later is itself an `InstancePolicyChange` ceremony.

## 3. Reload

### Propagation

Each process runs a `SettingsListener` hosted service. It holds one dedicated connection
(`Pooling=false`, TCP keepalive on) and listens on `modularca_settings`.

- A write sends `pg_notify` inside its transaction. PostgreSQL delivers it only on commit, so a
  node never hears of a change it cannot read.
- On notification the node reads every section with `Revision` above its applied revision,
  validates them, verifies them (above), unwraps secrets, builds a new snapshot and swaps it.
- A **30-second poll** of `max(Revision)` covers a dropped connection, a missed notification,
  and a connection pooler in transaction mode, where `LISTEN` does not work. On reconnect the
  node always does a full reload.
- The writing node applies its own change immediately after commit, so the API response
  reflects it.
- The signer runs no listener and reads no settings.
- An ingress-only process listens like any node. It reads few sections, but it keeps the same
  state reporting.

On a warm standby nothing runs against the replica, and `LISTEN` is refused during recovery
anyway. On promotion, nodes start and do a full load from the promoted database. The standby
gets the settings by replication. Its host-local files and its signer directory are provisioned
separately, which is the point of those classes.

### Snapshots and .NET options

A snapshot is the effective value of every instance-wide section at one revision: defaults, then
the database document, then environment values, plus unwrapped secrets. The swap is a single
reference assignment, so a reader sees one revision or the next, never half of one.

Consumers bind per section through **`IOptionsMonitor<TSection>`**, fed by the store. Each
section registers an `IConfigureOptions<T>` that copies the section out of the current snapshot,
and an `IOptionsChangeTokenSource<T>` that fires when a revision touches the section. `CurrentValue`
is cheap, and `OnChange` is how a component rebuilds itself.

**A custom `IConfigurationProvider` is not used.** Configuration binding flattens values to
strings and **merges lists by index into their defaults**. `NetworkAudit.ExcludePaths` (default
`/health`, `/metrics`) and `ComplianceScan.DeprecatedAlgorithms` would silently gain or keep
entries the admin removed, and the `JobTimeouts` dictionary would merge rather than replace. The
documents are already typed JSON for the existing classes, and deserialising them directly keeps
replace semantics and types exact.

### The bridge, and how consumers move

Stage 1 keeps the `SystemConfig` singleton. At startup it is filled from the file for classes a
to c, and from the store for d and e. In stage 2, a swap reassigns each changed section property
on the singleton (`config.Email = snapshot.Email`). A reference assignment is atomic, so every
consumer that re-reads `_config.Email.X` per call keeps working and now goes live on every node.

Reassignment breaks the consumers that held a sub-object or a list. That is the reason for the
migration order.

| Group | Files | Treatment |
|---|---|---|
| Constructor captures | 6: `IpWhitelistMiddleware`, `JwtIpBindingMiddleware`, `MtlsMiddleware`, `PlainHttpBodyLimitMiddleware`, `RequestAuditMiddleware`, `SiemLogFormatter` | moved to `IOptionsMonitor` in stage 2, before the swap ships. They are also four of the restart items that become live. |
| Writers | 6 classes and the scheduler registry's setters: `AdminConfigController` (24 PUTs and the restart POST), `AdminLdapController`, `AdminSchedulerController` (3), `AdminWebTlsController`, `AdminBackupController` (2), `WebTlsProvisioningService` | stage 1: instance-wide writes go to `ISettingsStore`. The web TLS and backup mode writes are host-local and keep `ConfigYamlWriter`. |
| Startup and command line | 7: `StartModularCA`, `SignerRole`, `UpgradeCheckCommand`, `BackupRestore`, `BootstrapModularCA`, `Unlocker`, `LegacyDatabaseGuard` | read the store or the file once, as their class says |
| Per-call readers | about 54 (controllers, filters, services, 15 scheduler jobs through `SingletonCronJob` and `PerRowScheduledJob`) | already live through the bridge; moved to per-section monitors one section per commit in stage 3 |
| Never read it | 10 classes inject `SystemConfig` and do not use it | drop the parameter |
| Tests | 38 test files construct a `SystemConfig` | a test helper builds snapshots, so tests do not hand-wire monitors |

When stage 3 ends, `SystemConfig` holds only classes a to c, renamed `HostConfig`, and nothing
mutates it at run time.

### Making restart items live

Some items are cheap to make live and worth it:

- The JWT key, through `IssuerSigningKeyResolver` over the monitor, with the previous key
  accepted for one access-token lifetime.
- Issuer and audience, by clearing the scheme's entry in `IOptionsMonitorCache<JwtBearerOptions>`.
- CORS, through an `ICorsPolicyProvider`.
- HSTS, with the middleware as the only reader.
- The four middleware captures above.
- `Est.TrustAnchorRefreshSeconds`.
- `CertPolicy.RsaSignaturePadding`, replacing the static with a monitor read in `KeyAlgorithmPolicy`.
- The syslog sink, behind a swappable wrapper.

These stay restart, and are declared so:

- The listeners and ports.
- The SNI names (`Mtls.AuthSubdomain`, `Est.AuthSubdomain`, `PublicDomain` for WebAuthn).
- `Mtls.Enabled`, `WebAuthn.Enabled` and `RelyingPartyName`.
- `Http.SwaggerEnabled` and `Metrics.Path`, which are route registration.
- Redis and Data Protection.
- The forwarded headers.

### "Needs restart"

Each node writes its `SettingsNodes` row when it applies a revision, and every 60 seconds:

- `AppliedRevision`.
- `StartedRevision`, the revision it started at.
- `PendingRestart`, the restart-class paths changed by revisions after `StartedRevision`.
- `EnvPaths`, the names of its environment overrides. Values are never recorded.
- `Problems`: verification failures, unwrap failures, a revision it refused.

A restart clears `PendingRestart`.

In the console, a section with pending items shows **Saved** and **In effect** side by side, per
node: "`Http.CorsOrigins` saved at revision 812; in effect on ca2 (enrollment); ca1 (control)
needs a restart." A banner across the console counts the nodes that need a restart. The
existing restart control restarts the node serving the console. Restarting another node is open
question 5.

### A node that is briefly behind

Settings are eventually consistent across nodes. The usual delay is notification latency
(milliseconds), and the worst case is the 30-second poll. That is stated in the console, not
hidden. While it lasts, an enrollment node can issue under the previous certificate policy and a
validation node can apply the previous IP exemptions. Every revision is applied as a whole, in
order, so no node ever runs a mix of two revisions.

The API response to a security-tier change waits up to five seconds for live nodes to report
the revision. It returns which nodes have applied it and which have not, and does not fail
because of a slow node.

A node that cannot apply a revision keeps its previous snapshot for that section. Causes include
a validator from a stricter build, a failed integrity check, or a secret it cannot unwrap. The
node reports the problem and raises a Critical alert. It retries on the next notification or
poll.

### Secrets and the signer

A node unwraps settings secrets when it loads a snapshot and keeps them in memory, as it keeps
them in `SystemConfig` today. A signer that goes away after that costs nothing until the next
change to a secret.

At start, a node in remote-signer mode waits for the signer, within `Schema.WaitSeconds` like the
other start conditions, before serving anything that needs a secret. The JWT secret is the one
that matters, because the console needs it. Every other secret fails soft:

- Without the LDAP bind password, LDAP sign-in is unavailable and the readiness page says why.
- SMTP and webhook deliveries pause.

The HSM case, where the designated key cannot seed a KEK, follows `signer-hardening.md`.

## 4. Precedence

Highest first:

1. **Command line.** `--role` only, as today.
2. **Environment.** `MODULARCA__<Section>__<Key>`, generalised from today's 13 names to every
   key of classes a, c, d and e. Lists are given as JSON. The existing names keep working
   unchanged.
3. **Database.** Classes d and e.
4. **Host-local file.** Classes a and c in `config.yaml` and `db.yaml`.
5. **Built-in defaults.**

The signer reads its own directory and its environment, and nothing else.

Environment values still win. Containers configure through the environment and orchestrator
secrets. Whoever sets a process's environment already controls the host, which is more privilege
than any console admin has, so refusing it would protect nothing and break every container
deployment. What changes is visibility:

- A setting from the environment shows **Set by environment** with the variable's name and the
  node, and cannot be edited. The API refuses a write to it with 409 `SETTING_FROM_ENVIRONMENT`.
  Today the write lands in memory, is kept out of the file, and is quietly lost at restart.
- Each node records the names of its environment overrides. The console flags a setting that is
  overridden on some nodes and not on others.
- When a node's set of overridden names differs from its last start, it appends a
  `SettingsEnvironmentOverride` audit row naming them. Changes are audited without one row per
  restart.

Host-local and database keys do not overlap by construction. An instance-wide key found in
`config.yaml` after the import is ignored, with a startup warning that names it and says where the
setting lives now. `/health/ready` reports it too.

## 5. Break-glass

A settings change can lock admins out:

- `IpWhitelist.Enabled` with rules that exclude them.
- `Mtls.RequiredPaths` without a proxy that forwards certificates.
- `Security.BindJwtToIp` behind a NAT that moves.
- `Security.EnforceRefreshTokenPoP`.
- `WebAuthn.EnforceForGroups`.
- A CORS list that excludes the console's origin when it is served cross-origin.
- LDAP pointed at the wrong directory for accounts that only have directory passwords.

**The offline path is a command, not a file.**

```
ModularCA.API --settings list
ModularCA.API --settings get <Section>[.<Path>] [--revision N]
ModularCA.API --settings set <Section>.<Path> <value> --reason "<text>"   (secrets from stdin)
ModularCA.API --settings history <Section>
ModularCA.API --settings rollback <Section> --to <revision> --reason "<text>"
ModularCA.API --settings export [--out file.yaml] [--legacy-yaml]
ModularCA.API --settings import <file.yaml> [--section S] [--dry-run] --reason "<text>"
ModularCA.API --settings adopt
```

It follows `--unlock-user`:

- It runs on the host as the service user, never as root, with the `db.yaml` credentials. So it
  grants nothing that reading `db.yaml` does not.
- It writes through the same `SettingsStore`: same validators, same history, same revision.
- `pg_notify` makes a running node pick the change up live, or mark it pending restart.
- The history records the actor `host:break-glass`, with the host name and the OS user. The audit
  row goes into the hash chain through `AuditHashChainService` and the `db.yaml` audit
  credentials.
- The next control start raises a Critical `SettingsChangedOnHost` alert.
- It does not ask for step-up or a ceremony. Host access is the higher privilege, and the record
  is what makes it accountable.
- It has no `--force`. The validators exist to keep the next start working, which matters most in
  an emergency.
- Setting a secret needs the signer: in process, or through the node's signer channel. The other
  sets do not.

**A file override that wins was rejected:**

- It is exactly the unaudited, unversioned edit path this design removes.
- It persists silently after the emergency, while the console shows values that are not in
  effect.
- It applies to one host, so it splits a multi-host instance's behaviour.
- It buys nothing the command does not. Both need a shell on the host, and the command also
  works while the service runs.

For a container where an exec is not possible, the environment is the restart-time lever, for
example `MODULARCA__IPWHITELIST__ENABLED=false`. It is loud: a startup audit row and a "set by
environment" badge until someone removes it.

The `Whitelists` rules are not settings, and `IpWhitelist.Enabled=false` is the master switch
that covers a lockout by rule.

## 6. Migration

### When and where

The import runs at the **control role's first start on the new build**, in the schema phase. It
runs after the migrations that create the tables, under the same migration lock, before the host
is built. Other roles already wait for the control role's migrations, so when they see the
schema, the import is done too.

It does not run in `ModularCA.Migrate`, which exists for the MariaDB move and does not run on a
PostgreSQL-to-PostgreSQL upgrade. It does not run in `--upgrade-check`, whose contract is
read-only.

### The import

1. Load `config.yaml` with `YamlConfigLoader`, including the 0.4.0 legacy-key upgrades.
2. Take the class d and e keys **present in the file**. Absent keys stay default, so the store
   holds the same sparse picture the file did.
3. Validate with the load-time rules. A failure stops the start with exit 3 and names the key.
   It is the same failure the current startup would have had.
4. Wrap the used secrets through the signer and hash the API keys. Skip secrets that come from
   the environment.
5. In one transaction, write one revision per section with source `Import`, actor
   `host:<hostname>:import`, and a `SettingsImported` audit row carrying the file's SHA-256 and a
   hash per section. Record a `SettingsImports` row.
6. After the commit, keep the original as `config.yaml.pre-settings-<timestamp>.bak`, owner-only,
   the way `ModularCA.Migrate` keeps `.mariadb-*.bak`. Then rewrite `config.yaml` in place with
   `WriteKeepingAccess`, so owner, group and mode are kept. The new file holds class a and c keys
   only, under a header saying where the rest went.

A failed transaction changes nothing. A failed rewrite after the commit leaves instance-wide keys
in the file. They are ignored with a warning, and the next start retries the rewrite. Running the
import twice is a no-op, because the `SettingsImports` row exists.

New installs never have an instance-wide file. `BootstrapDatabaseSetup.WriteConfigFile` splits:
host-local keys go to `config.yaml`, and the rest is seeded into the store with source
`Bootstrap`. The JWT secret is wrapped under the bootstrap purpose.

### Multi-host installs

The control host's file wins the import, because it is the only file the console ever wrote.
Every other host does this at its first start on the new build:

- It computes the canonical hash of each section of its own file's class d and e keys.
- It compares each hash with the store's imported baseline for that section. If the section has
  changed since the import, it compares with the current document instead.
- If they are equal, it rewrites its file to host-local keys, with a backup, and continues.
- If they differ, it **refuses to start** with exit 3. It lists every differing key with both
  values (secrets as "differs") and the two remedies:
  - `--settings adopt` takes the store's values and strips the local keys.
  - `--settings import --section S` makes this host's values the instance's, audited, and then
    adopts.

Refusing was chosen over taking the control host's values silently. A deliberately different
value on one host is real today: a validation host with network audit off, for example. Making
it instance-wide changes that host's behaviour, and the operator should decide that, not
discover it. `--upgrade-check` reports the difference before the upgrade (below), so a prepared
operator never meets the refusal.

### What `--upgrade-check` reports

Before the import, against a file-only install:

```
Settings: config.yaml moves to the database at the control role's first start.
  23 sections, 7 secrets (2 from the environment, not imported).
  Kept in this host's config.yaml: Https.Port, Https.ListenAddress, ... (19 keys)
  Leaving the admin API: SshCa.SshKeygenPath, PolicySync.PolicyDirectory
  Section fingerprints (compare across hosts): Email 3f2a..., Security 9c1d..., ...
```

After the import, on any host:

- "Settings: in the database at revision R; this host's config.yaml holds host-local keys only."
- Or, with exit 3: "this host's config.yaml sets instance-wide keys that differ from the database:
  ...". That is the same verdict the start would reach.

### Downgrade

Downgrade is a restore, as for every schema change. An older build refuses a schema newer than
itself (`SchemaStartup`, `NewerThanBuild`), so the store's migration already makes the database
one-way.

For the file, the import's `.bak` is the pre-upgrade `config.yaml`. `--settings export
--legacy-yaml` renders a complete pre-store `config.yaml` from the current store, with secrets
unwrapped (it needs the signer), for an operator who restores an older database and wants the
settings they have changed since.

## 7. Backup and restore

The settings travel in the database dump: `Settings`, `SettingsHistory`, `SettingsSecrets` and
`SettingsImports`. The secrets in the dump are wrapped under the source keystore's designated
key. A restore brings the keystore back through the signer, so they unwrap after the restore as
the Data Protection ring does. A database restored without its keystore cannot read them, which
is the point. `SettingsNodes` is runtime state and is emptied after a restore.

The archive still needs these from `config/`:

- `config.yaml`, now host-local only. That is a reference for rebuilding a host, not settings.
  The archived copy also drops `Https.CertificatePassword` and `Signer.ClientCertificatePassword`,
  whose files are already deny-listed.
- `license.lic`.
- The wrapped bundles under `secrets/`: the Data Protection ring and the SSH CA keys.

Nothing instance-wide needs the file any more, and no settings secret is in the archive outside
the signer's wrap. Today the archived `config.yaml` carries the JWT secret, the LDAP and SMTP
passwords and both API keys, protected only by the archive key.

**The restore keeps the target's host-local settings.** Today the restore merges the archive's
`config/` over the target's, so the source host's ports, certificate path and signer pins
overwrite the target's. Instead:

- When the target has a `config.yaml`, it is left alone. The archive's copy is written to
  `config/restored/config.yaml.<archive>` for reference.
- When the target has none, which means a bare host with only `db.yaml`, the archive's copy is
  installed.

The environment on the target still wins. The restore appends a revision with source `Restore` to
every section, so the history shows the jump and each node reloads at start.

## 8. API and console

### Endpoints

The 24 `PUT /api/v1/admin/config/*` endpoints keep their paths and bodies and write through the
store. They gain:

- an optional `If-Match`;
- `revision`, `appliedOn` and `restartRequired` in the response;
- 202 with a ceremony id when the change needs approval;
- 409 for a conflict or an environment-sourced key.

`PUT /config/ssh-ca` and `PUT /config/policy-sync` answer 410 and point at the host file. The
messages that say "restart required" are generated from the reload attributes, which fixes the
integration API and cert-manager cards, whose changes are in fact live.

New endpoints, all for the system admin role. Reads are also open to system auditors.

| Method and path | Purpose |
|---|---|
| `GET /api/v1/admin/settings` | every section: effective values, source per property (default, database revision, environment variable, host file, command line), reload mode, ETag |
| `GET /api/v1/admin/settings/{section}` | one section, with `ETag` |
| `PUT /api/v1/admin/settings/{section}` | generic full-section write with `If-Match`, for settings that have no card today: WebAuthn, Audit, Est, the ACME internals, HSTS, `EnforceRefreshTokenPoP`, `LdapAuth.RequireTls`, webhook endpoints, the integration space scopes, `RsaSignaturePadding`, SourceCode, Msae. Without it, moving the file would leave these with no way to change them but the CLI. |
| `GET /api/v1/admin/settings/{section}/history?before=&limit=` | revisions: actor, time, source, reason, changed paths, ceremony, audit id |
| `GET /api/v1/admin/settings/{section}/history/{revision}` | the document at a revision |
| `GET /api/v1/admin/settings/{section}/diff?from=&to=` | path-level diff. `from` can be `default`. Secrets show as "changed". |
| `POST /api/v1/admin/settings/{section}/rollback` | `{ toRevision, reason }`. Step-up, with the same tier rules as a write of that document. Creates a new revision. **Secrets are never rolled back**: going back to an old password or key would restore exactly what someone may have rotated away from. |
| `GET /api/v1/admin/settings/nodes` | nodes, applied and started revisions, pending restart, environment overrides, problems |
| `GET /api/v1/admin/settings/export` | YAML of every section, secrets omitted, for review and GitOps diffs |

Approvals use the existing ceremony endpoints and pages.

### Settings page

- **A source badge on every field**:
  - "Default".
  - "Saved, rev 812 by alice, 2 h ago".
  - "Environment: MODULARCA__EMAIL__PASSWORD (ca1, ca2)". Read-only.
  - "Host file on ca1". Read-only, with the host named, because host-local values differ per node.

  The page shows host-local values as a read-only panel per node.
- **Saved and in effect.** A restart-class field shows both values when they differ, with the
  nodes that need a restart. The static Live and Restart tags on the section headers become
  per-field badges from the attributes. A banner across the console counts the nodes that need a
  restart.
- **History**: a drawer per section, with revisions, actor, reason, a ceremony link, a diff
  against the previous revision or the default, and "Restore this version". This fits the
  drawer pattern of the console consolidation.
- **Conflicts**: on a 409 the card shows "Changed by bob 2 minutes ago", the diff, and Reload.
- **Reason**: an optional reason on every save, and a required one for security-tier changes and
  rollbacks.
- **Pending approval**: a section with a pending `SettingsChange` ceremony shows the proposal and
  who has approved, and its card is read-only until the ceremony resolves.

## 9. Policy sync and the migrate tool

**Policy sync** is a host-written directory of YAML that changes profiles without going through
the console's step-up. It stays, because it is an opt-in GitOps path, but its trust boundary
becomes explicit:

- The section is host-local, so whoever controls the host decides whether it runs and where it
  reads. An admin over HTTP no longer can.
- `POST /api/v1/admin/policy/import` keeps its step-up and its audit.
- The startup sync, which today only logs, appends a `PolicySyncExecuted` audit row with the host
  and the SHA-256 of each file it read.

Settings get the same GitOps shape without a watcher. `--settings export` and `--settings import
--dry-run` give a diffable YAML, and a pipeline applies it with `--settings import` on the control
host, audited as a host actor. A watched settings directory was not added, because it would be the
file override that section 5 rejects.

**`ModularCA.Migrate`** touches only `db.yaml` and the `DB` section, which are class a and stay
in files. It needs no change. A 0.3 MariaDB install migrated straight to a store build has no
settings tables in its source. The tables come from the 0.4 migrations, and the import runs at
the first start, as for any upgrade.

## 10. Stages

| Stage | What | Effort |
|---|---|---|
| **1a. Store, import, read path** | The tables and migration. `ISettingsStore`, with history, revision, `If-Match`, audit-first writes and the integrity check. The class and reload attributes with their architecture test. The validators and change policies extracted from the controllers. Secrets wrapped through the signer, with a new `SecretKind`, and API keys hashed. The import, the strip and the multi-host comparison. Bootstrap seeding the store. The 33 write sites moved to the store. `SystemConfig` filled from file and store at startup, so behaviour on one host is unchanged. The generic section `PUT`. SSH and policy-sync paths leaving the API. `--upgrade-check` reporting. | L |
| **1b. Break-glass CLI** | `--settings list/get/set/history/rollback/export/import/adopt`. It ships with 1a, because settings must not leave the file before the offline path exists. | M |
| **2. Live reload across nodes** | The listener, the poll backstop and full reload. Snapshot swap through the bridge. The six constructor captures moved first. `SettingsNodes`, pending-restart tracking, environment override recording, the `/health/ready` entry, and the five-second apply report. | L |
| **3. Consumers onto monitors** | Per-section `IOptionsMonitor<T>`, one section per commit, through the about 54 per-call readers. The live conversions in section 3 (JWT key resolver, scheme options, CORS provider, HSTS, EST refresh, RSA-PSS, syslog wrapper). `Msae` joins the store. Dead injections removed. `SystemConfig` reduced to `HostConfig`. | L |
| **4. History and console** | The history, diff, rollback, nodes and export endpoints. Source badges, saved against in effect, the history drawer, conflict handling and read-only environment fields. | L |
| **5. Approvals** | `CeremonyType.SettingsChange`, the weakening declarations, `RequireSettingsCeremony`, and the pending-approval UI. Confirm-or-revert for lockout-capable keys if the owner wants it (open question 7). | L |
| **6. Retire the runtime YAML writer** | `ConfigYamlWriter` keeps only the host-local web TLS and backup-mode writes. The bridge is deleted. | S |

**The riskiest step is 1a's import and strip.** It is one-way, it runs on every install at
upgrade, and it rewrites a file operators have hand-edited for years. A misclassified property
silently loses a per-host value, and an unwrap problem stops the control role. The mitigations:

- the attribute classification with its architecture test;
- `--upgrade-check` reporting the plan and the fingerprints before anything runs;
- the kept `.bak`;
- refusing on divergence rather than guessing;
- a live proof on ca4 with a split install (control, enrollment, validation on separate units)
  before release.

The second risk is the new dependency: a control start now needs the signer to unwrap the JWT
secret.

### Built so far

As of 2026-10-06. The instance-wide settings and the secrets the node uses are read from the
store and saved to it.

- `[Setting]` on every leaf of `SystemConfig`, and `SettingsCatalog`: the keys, the classes, and
  the check and canonical spelling of a value.
- The `Settings`, `SettingsSecrets`, `SettingsHistory` and `SettingsState` tables (migration
  `SettingsStore`).
- `ISettingsStore`: load, write (set and clear, expected versions, one revision per write,
  history, audit before save, retry on a lost race) and per-setting history. It refuses a key
  that is unknown, host-local, signer-local or bootstrap, and a value of the wrong type.
- Secrets in the store: wrapping through the signer bound to the setting's key, hashing for
  the two API keys, and `ApplySecretsAsync` to read wrapped secrets back. In the signer:
  envelope version 2, the `SettingSecret` kind and the `Configuration` purpose.
- **The move** (`SettingsRuntime.ImportAsync`): at the control role's first start, every
  instance-wide setting that differs from its default is written to the store with source
  `Import` and actor `host:<name>:import`, and `SettingsState.ImportedAt` is set. It runs once.
- **The read path** (`SettingsRuntime.Apply`, from `SettingsStartup` after the schema check):
  once the settings are moved, each instance-wide setting is put back to its default and the
  stored values are applied, so the file cannot decide one. A value the file still gives is
  reported in the log. The few settings startup reads before the database is reachable (the
  log level, RSA padding, the cron checks) are read again afterwards.
- **The save path** (`SettingsPersistence`, called through `ConfigSave` by every settings
  endpoint): the endpoints still change `SystemConfig` in memory; saving then writes whatever
  differs from the store to the store, and the file with host-local settings only.
- **The file** (`ConfigYamlWriter.Serialize(config, withoutPaths)`): the control role rewrites
  its `config.yaml` without the stored settings whenever the file still sets one, keeping a
  copy as `config.yaml.pre-settings-<time>.bak`.
- **`--settings`** (`SettingsCommand`): `list`, `get`, `set`, `clear` and `history`, over the
  same store, with the `db.yaml` credentials and a host actor.

Where this differs from the sections above:

- **The six wrapped secrets are moved; the two hashed API keys are not.** `SettingsStartup`
  opens a signer before the web host is built: the node's own keystore, unlocked as the node
  unlocks it (`MaintenanceSigner.CreateUnlocked`), or the remote signer it is configured for.
  The control role stores each secret the file holds and nothing has stored yet; every role
  reads the stored ones back. A secret is taken out of the file once it is stored, so one
  that could not be wrapped stays there and keeps working. The copy of the file kept at the
  rewrite has the stored secrets removed.
- **A node that cannot read its JWT secret runs on a temporary one.** The design had it answer
  503 to every sign-in until the signer returned. It signs sessions with a secret made up for
  that start and says so, which keeps the console reachable to put things right; the sessions
  end with the process. The other secrets wait, as designed.
- **The single integration API keys stay in `config.yaml`** (open question 11): named API keys
  replace them, so they are neither hashed into the store nor refused for being short.
- **The JWT secret is not rotated at the move**, which `signer-hardening.md` asks for because
  earlier archives hold it in the clear. The log says that earlier copies and archives still
  hold the moved secrets.
- **Reload is declared as it is today**, not as designed. The console shows it to the person
  saving, so `[Setting]` says Restart for the twenty-two settings something reads once at
  start, and each moves to Live when its reader is made to follow changes (the "Making restart
  items live" list in section 3).
- **Sparse by value, not by presence in the file.** The console has always written the whole
  configuration back, so a key being present in `config.yaml` says nothing about whether
  anyone chose its value. What is stored is what differs from the default.
- **No `SettingsImports` table.** The move is marked on `SettingsState`. The file's hash and
  per-section fingerprints are not recorded.
- **Other hosts do not compare or refuse.** A non-control host leaves its file alone and
  ignores, with a warning, an instance-wide value in it. Refusing to start on a difference,
  `--settings adopt` and `--settings import` are not built.
- **No reload while running.** A change reaches the node that saved it at once, because the
  endpoint changed its memory, and every other process at its next start. The listener, the
  poll and `SettingsNodes` are stage 2.
- **The host command checks a value's type and nothing more.** The per-section validators are
  still inside the controllers, so `--settings set` can store a value the console would have
  refused. The cron expressions are the exception: a start refuses a stored one that does not
  parse.
- **Two audit records per console save.** The endpoint still writes its own `ConfigUpdated`
  record naming the section, and the store writes one naming each key with its value before
  and after.
- **`--upgrade-check` does not yet report** what will move.

Not built: per-section validators and change policies as their own types,
bootstrap seeding the store directly, the generic section endpoint, the rest of the host
command (`rollback`, `export`, `import`, `adopt`), and stages 2 to 6. The store does not link
a row to its audit record, so the integrity check in section 2 has nothing to check against.

## 11. Open questions for the owner

1. **Member names.** Is `Https.PublicDomain` the instance's one public name (instance-wide, as
   proposed), with any per-member names as a new host-local list? Or does each HA member publish
   under its own name?
2. **JWT secret.** Should it be in the database, signer-wrapped, so the console needs the signer
   at control start (proposed)? Or host-local per member, so failover costs one refresh and has
   no signer dependency?
3. **Settings ceremony switch.** Should it be a new `RequireSettingsCeremony` (proposed, off on
   upgrade) or reuse `RequireKeyCeremony`? Is the security tier the right list? Should *every*
   change in it need approval, not only weakening ones?
4. **Environment scope.** Should environment overrides be allowed for instance-wide keys
   (proposed, flagged and audited), or only for host-local keys and secrets? The narrower rule is
   harder to bypass and would break any container that sets a policy through the environment.
5. **Remote restart.** May the console restart another node, through a restart request on the
   settings channel with step-up? Or does restart stay per node?
6. **Existing policy tables.** `SecurityPolicy`, `PasswordPolicy`, `LdapPublisherPolicy`,
   `FeatureFlags` and the rate-limit policy are already in the database, without history. Should
   they move under the same history, diff and rollback, later?
7. **Confirm-or-revert.** Should a change to a lockout-capable key apply provisionally, and
   revert after five minutes unless the admin confirms from a request that passes the new
   setting?
8. **mTLS anchors.** Should `Mtls.TrustedCaCertPaths` become certificates stored in the database
   (instance-wide), instead of host file paths? The database fallback to the enrolled mTLS signing
   CAs already covers the common case.
9. **`Logging.MinLevel`.** Should it be instance-wide (proposed), or host-local, so one node can
   be debugged alone?
10. **Visor.** When the visor changes settings through the API, is its scoped role allowed
    security-tier changes at all, or only routine ones?
11. **Existing short API keys.** The store hashes an API key and refuses one under 32
    characters. An install whose `IntegrationApi.ApiKey` or `CertManager.ApiKey` is shorter
    cannot have it imported as it is. Should the import refuse to start until the operator
    sets a longer key, or generate a new key and show it once, or leave the short key working
    from `config.yaml` with a warning until it is replaced?

    Named API keys (the `ApiKeys` table, 2026-10-06) change the weight of this question. They
    are generated by the server, so they are always long enough, and each client can be moved
    to one before the single configured key is touched. A fourth answer is then available:
    the import leaves the configured key out of the store entirely, tells the operator to
    issue named keys, and the single key is retired in a later release.

## Found along the way

- **Console changes never reach other hosts.** See "Why". `CertPolicy` is enforced by the
  enrollment role and `IntegrationApi` is served by it, yet both are edited on the control host.
- **Half-applied changes.** `BindJwtToIp` and `JWT.Secret`/`Issuer`/`Audience` take effect in
  token issuance at once and in validation only after a restart. `IpWhitelist.Enabled`,
  `NetworkAudit.*` and `Mtls.RequiredPaths` are saved, audited and alerted on, and stay without
  effect until restart, even on the control host.
- **Wrong restart messages.** The integration API and cert-manager cards say "restart required",
  but their filters read the live value.
- **Settings with no API.** The file is the only way to change `WebAuthn.*`, `Audit.FailMode` and
  the retention days, `Est.*`, the ACME internals, `Http.Hsts`, `ForwardedHeaderHopLimit`,
  `Security.EnforceRefreshTokenPoP`, `LdapAuth.RequireTls`, `Webhook.Endpoints`, the integration
  space scopes, `CertPolicy.RsaSignaturePadding` and `SourceCode`. Hence the generic section
  `PUT` in stage 1a.
- **Admin-settable host paths.** `PUT /config/ssh-ca` sets the executable path and
  `PUT /config/policy-sync` sets a directory the server reads. Both are closed by making them
  host-local.
- **Restore overwrites host settings.** It merges the archive's `config/` over the target's,
  overwriting the target's listeners, certificate path and signer pins with the source host's.
- **Plaintext secrets in archives.** The archived `config.yaml` carries plaintext secrets under
  the archive key only, while the Data Protection ring beside it is signer-wrapped.
- **Torn reads.** In-place mutation of the shared singleton lets a request read half an update,
  and replacing a list leaves any holder of the old list on old values.
- **Unused code.** `Hsm.KeyMappings` is read by nothing, and ten classes inject `SystemConfig`
  and never read it.
- **`Msae` options are outside `SystemConfig`.** They come from `appsettings.json` and the
  environment, so a node's template OID arc can differ from another's without anyone seeing it.
