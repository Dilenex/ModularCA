export default function TenantModelDiagram() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Multi-Tenancy Model
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                A ModularCA deployment is one instance. The instance owns its own infrastructure CAs (the
                System Signing CA and any SSH CAs) and the system groups; none of them belongs to a tenant.
                Tenants (organizations) own the CAs created in them, CAs have groups, and groups contain
                users with role-based permissions. Bootstrap creates one tenant, from the config's
                Organization name, which owns the root CA. Since 0.4.0 there is no "System" tenant.
            </p>

            {/* Model Diagram */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Instance and Tenants</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  +----------------------------------------------------------------------+
  |                    ModularCA Instance                                |
  |   policy: SecurityPolicy (RequireKeyCeremony, approvals, ceiling)    |
  +----------------------------------------------------------------------+
  |                                                                      |
  |  Instance CAs (no tenant)           +-----------------------------+  |
  |  +------------+  +------------+     |   Tenant "Acme"             |  |
  |  | System     |  | SSH CAs    |     |   policy: its own fields    |  |
  |  | Signing CA |  |            |     +-------------+---------------+  |
  |  +-----+------+  +------------+                   |                  |
  |        |                             +------------+----------+       |
  |  +-----+----------------------+      |                       |       |
  |  | system_system-signing-ca_* |   +--+------+  +---------+---+       |
  |  +----------------------------+   | Acme    |  | Acme      |         |
  |                                   | Root CA |  | Issuing CA|         |
  |  System groups (no tenant)        +---------+  +-----+-----+         |
  |  - system-super                                      |               |
  |  - system-admin                  +-------------------+----------+    |
  |  - system-operator               | acme_issuing-ca_admin        |    |
  |  - system-auditor                | acme_issuing-ca_operator ... |    |
  |       |                          +-------------------+----------+    |
  |  +----+--------+                               +-----+--------+      |
  |  | Users       |                               | Users        |      |
  |  | - admin     |                               | - alice      |      |
  |  +-------------+                               +--------------+      |
  +----------------------------------------------------------------------+
`}</pre>
                </div>
            </section>

            {/* The Instance */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">The Instance</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Instance-wide settings belong to the instance, not to a tenant. A CA, group, Kerberos realm,
                    grant or role assignment with no tenant is at instance scope.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>The System Signing CA and SSH CAs are instance CAs: they have no tenant</li>
                    <li>The system groups (system-super, system-admin, system-operator, system-auditor) have no tenant</li>
                    <li>Instance CA policy lives on the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">SecurityPolicy</code> row
                        (Settings, Security Policy): RequireKeyCeremony, CeremonyRequiredApprovals, MaxValidityDays and ValidityCeilingBehavior</li>
                    <li>Scopes are independent: the instance's policy governs instance CAs only, and a tenant's policy governs its own CAs only; nothing merges</li>
                    <li>Members of a system group, or of an instance CA's group, see the instance CAs</li>
                </ul>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Upgrading from 0.3.x:</span> release 0.4.0 folds the former System
                        tenant into the instance. Its values move to the instance's policy as they were, and its
                        tenant-wide <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">org-system-*</code> groups are removed.
                    </p>
                </div>
            </section>

            {/* Organization Tenants */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Organization Tenants</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Organization tenants represent separate customers or departments sharing the same
                    ModularCA deployment. Each tenant has full isolation of their CA hierarchy, users,
                    and certificates.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Created by system administrators via /admin/tenants</li>
                    <li>Own their own CA hierarchy (can have their own root or use shared intermediate)</li>
                    <li>Isolated user accounts and group memberships</li>
                    <li>Separate certificate inventory and audit logs</li>
                    <li>Independent profile and template configuration</li>
                    <li>Can be enabled or disabled without affecting other tenants (disabled tenants cannot issue certificates)</li>
                    <li>Support soft-delete
                        (<code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">IsDeleted</code>) -- hidden
                        by the soft-delete query filter, which is the only global filter left; it filters no tenant</li>
                    <li>URL-safe <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">Slug</code> field
                        for route segments and API filters</li>
                </ul>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Tenant Entity Fields</h3>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Field</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Description</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">RequireKeyCeremony</td>
                            <td className="py-2">When true, creating, revoking or deleting one of this tenant's CAs requires a multi-party key ceremony (the instance has its own)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">CeremonyRequiredApprovals</td>
                            <td className="py-2">Number of admin approvals needed before a ceremony can execute (default: 2)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">MaxValidityDays</td>
                            <td className="py-2">Longest validity a leaf certificate of this tenant's CAs may carry (0 = unlimited). Tenant quotas were removed in 0.4.0; quotas are per CA</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4 font-mono text-sm">CanBeDeleted</td>
                            <td className="py-2">Bootstrap-created tenants are protected from deletion</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            {/* Group Naming Convention */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Group Naming Convention</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Auto-generated CA groups are named
                    <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">&#123;tenantSlug&#125;_&#123;caLabel&#125;_&#123;role&#125;</code>,
                    with underscores between the three segments and a lowercase role. The tenant slug is part
                    of the name so two tenants can own CAs with the same label without colliding on the unique
                    group-name index; the underscores remove the hyphen-boundary ambiguity in a name like
                    <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">modularca_modularca-root-cert-1_admin</code>.
                    Instance CAs have no tenant, so their groups use the slug <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system</code>,
                    which no tenant may take. System-level groups use a <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-</code> prefix.
                </p>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Scope</th>
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Prefix</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Examples</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Tenant</td>
                            <td className="py-2 pr-4 font-mono text-sm">&mdash;</td>
                            <td className="py-2 font-mono text-sm">No auto-generated tenant-wide groups</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">CA-scoped</td>
                            <td className="py-2 pr-4 font-mono text-sm">{'{tenantSlug}_{caLabel}_'}</td>
                            <td className="py-2 font-mono text-sm">acme_webserver-ca_admin, acme_webserver-ca_operator</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Instance CA</td>
                            <td className="py-2 pr-4 font-mono text-sm">{'system_{caLabel}_'}</td>
                            <td className="py-2 font-mono text-sm">system_system-signing-ca_admin</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4">System (global)</td>
                            <td className="py-2 pr-4 font-mono text-sm">system-</td>
                            <td className="py-2 font-mono text-sm">system-admin, system-super</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            {/* Groups and Roles */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">CA-Scoped Groups and Roles</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Authorization is based on CA-scoped groups rather than global roles. When a CA is created,
                    groups are automatically generated using the CA label as a prefix. Users are added to groups
                    with a specific role level that determines their permissions.
                </p>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Auto-Generated Groups per CA</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    When a CA with label <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">webserver-ca</code> is
                    created inside tenant <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">acme</code>,
                    these four groups are generated automatically:
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    acme_webserver-ca_admin&nbsp;&nbsp;&nbsp;&nbsp;-- Administrator: full control over this CA<br />
                    acme_webserver-ca_operator&nbsp;-- Operator: issue and revoke certificates<br />
                    acme_webserver-ca_auditor&nbsp;&nbsp;-- Auditor: read-only access to logs and certs<br />
                    acme_webserver-ca_user&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-- Requester: self-service certificate requests
                </div>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r mb-4">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Note:</span> These groups are created automatically whenever a
                        new CA is provisioned. The group names are derived directly from the CA label, so a CA
                        labelled "Production-Web" produces groups like "Production-Web-Admin", "Production-Web-Operator", etc.
                    </p>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">System Groups</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    System groups provide global access across all CAs and tenants in the entire deployment.
                    These use the <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-</code> prefix:
                </p>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm mb-4">
                    system-super&nbsp;&nbsp;&nbsp;&nbsp;-- Full access to everything (superuser)<br />
                    system-admin&nbsp;&nbsp;&nbsp;&nbsp;-- Full platform administration<br />
                    system-operator -- Manage all CAs and certificates<br />
                    system-auditor&nbsp;&nbsp;-- Read-only access to all audit data
                </div>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r mb-4">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Important:</span> The <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-super</code> group
                        grants unrestricted access to all resources across every tenant. Membership should be tightly controlled.
                    </p>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Role Levels</h3>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Each group carries a role level that determines the permission tier. Lower numbers indicate
                    higher privilege:
                </p>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Role</th>
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Level</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Permissions</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">Admin</td>
                            <td className="py-2 pr-4 font-mono text-sm">1</td>
                            <td className="py-2">Full control: create CAs, manage profiles, manage groups, issue/revoke certificates, view audit</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">Operator</td>
                            <td className="py-2 pr-4 font-mono text-sm">2</td>
                            <td className="py-2">Operational: issue/revoke certificates, approve requests, generate CRLs</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">Auditor</td>
                            <td className="py-2 pr-4 font-mono text-sm">3</td>
                            <td className="py-2">Read-only: view certificates, audit logs, compliance reports</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4 font-mono text-sm">User</td>
                            <td className="py-2 pr-4 font-mono text-sm">4</td>
                            <td className="py-2">Self-service: request certificates, view own certificates</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            {/* Quorum Settings */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Quorum Settings</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Groups can have quorum requirements for sensitive operations such as key ceremonies.
                    A quorum defines the minimum number of group members who must approve an action before
                    it can proceed.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Quorum is configured per group and applies to key ceremony operations</li>
                    <li>Typical use: require multiple Admin approvals before generating or rotating a CA key pair</li>
                    <li>A quorum of 1 means single-approval (default); higher values enforce multi-party authorization</li>
                    <li>Quorum checks are enforced at the service layer before any cryptographic material is accessed</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Key Ceremony Request
        |
        v
  +---------------------+     +----------------------+
  | Group Membership    |---->| Quorum Check         |
  | (is user in group?) |     | (enough approvals?)  |
  +----------+----------+     +----------+-----------+
             |                           |
        Yes  | No                   Met  | Not Met
             v                           v
        Continue                   Pending Approval
             |                     (wait for more
             v                      approvals)
  +---------------------+
  | Execute Ceremony    |
  +---------------------+
`}</pre>
                </div>
            </section>

            {/* Quota Enforcement */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Quota Enforcement</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Quotas are configured per CA, on the CA's admin group, and enforced at issuance time.
                    Tenant quotas (max CAs, certificates and users) were removed in 0.4.0.
                </p>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">Quota Types</h3>
                <table className="w-full border-collapse mb-4">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                            <th className="text-left py-2 pr-4 text-gray-900 dark:text-white font-semibold">Quota</th>
                            <th className="text-left py-2 text-gray-900 dark:text-white font-semibold">Description</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Max Certificates</td>
                            <td className="py-2">Active certificates per CA (set on the CA's admin group)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Max Pending Requests</td>
                            <td className="py-2">Pending requests per CA (set on the CA's admin group)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Rate Limit</td>
                            <td className="py-2">Maximum certificate issuance rate (per hour/day)</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4">Max Validity</td>
                            <td className="py-2">Maximum certificate validity, per tenant or for the instance</td>
                        </tr>
                    </tbody>
                </table>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Issuance Request
        |
        v
  +------------------+     +------------------+
  | CA Quota         |---->| Rate Limit       |
  | (per-CA limit)   |     | (per-hour limit) |
  +--------+---------+     +--------+---------+
           |                        |
      Pass | Fail              Pass | Fail
           v                        v
      Continue              429 Rate Limited
      409 Quota Exceeded
`}</pre>
                </div>
            </section>

            {/* Tenant Isolation */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Tenant Isolation</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    From 0.4.0 the isolation boundary is the instance; a tenant is a scope for delegating
                    administration, not a partition of data. There is no tenant query filter: each endpoint
                    that lists or reads rows of several tenants applies the caller's fence explicitly, and the
                    fence equals what authorization allows.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>CAs and groups carry a tenant ID; instance CAs and system groups carry none</li>
                    <li>The fence holds the tenants of the caller's groups, of tenant-scoped grants and roles on the user, and of the CAs the user holds grants on; instance rows need an instance group or a grant on an instance CA</li>
                    <li>A capability held at system scope (system operator, system auditor and the like) makes the fence instance-wide: every tenant's CAs are listed</li>
                    <li>CA labels and names are unique across the instance, so a label in a URL names one CA</li>
                    <li>A certificate profile is used only by a CA of its own scope, whatever the protocol</li>
                    <li>The Admin UI's scope switcher narrows what a caller may see; it never widens it</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Authenticated Request
        |
        v
  +---------------------+     +----------------------+     +---------------------+
  | Resolve the fence   |---->| Endpoint applies it  |---->| Return fenced       |
  | from all grants     |     | to rows it returns   |     | results             |
  +---------------------+     +----------+-----------+     +---------------------+
                                         |
                            Capability at system scope?
                                    |          |
                                   Yes         No
                                    |          |
                                    v          v
                              All tenants   Fenced tenants
                              visible       (+ instance rows)
`}</pre>
                </div>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Important:</span> Tenant isolation is application-level,
                        not database-level. All tenants share the same database. Each endpoint applies the
                        caller's fence, which the tenant resolution middleware stores for the request.
                    </p>
                </div>
            </section>
        </div>
    );
}
