export default function TenantModelDiagram() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Multi-Tenancy Model
            </h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed mb-8">
                ModularCA supports multi-tenancy, allowing a single deployment to serve multiple organizations
                with isolated CAs, users, and resource quotas. The tenant model is hierarchical: tenants own
                CAs, CAs have groups, and groups contain users with role-based permissions. Bootstrap creates
                two tenants: a "System" tenant (owns infrastructure CAs) and an organization tenant (from the
                config's Organization name, owns the root CA).
            </p>

            {/* Model Diagram */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Tenant Hierarchy</h2>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  +----------------------------------------------------------------------+
  |                       ModularCA Deployment                           |
  +----------------------------------------------------------------------+
  |                                                                      |
  |  +--------------------------+   +-----------------------------+      |
  |  |   System Tenant          |   |   Org Tenant "Acme"         |      |
  |  |   (Built-in)             |   |   (Created by admin)        |      |
  |  +------------+-------------+   +-------------+---------------+      |
  |               |                               |                      |
  |     +---------+---------+           +---------+---------+            |
  |     |                   |           |                   |            |
  |  +--+------+  +--------+--+     +--+------+  +--------+--+          |
  |  | Root CA |  | System    |     | Acme   |  | Acme      |          |
  |  |         |  | Signing   |     | Root   |  | Issuing   |          |
  |  |         |  | CA        |     | CA     |  | CA        |          |
  |  +----+----+  +--------+--+     +--------+  +-----+-----+          |
  |       |                |                           |                |
  |  +----+-------------+  |     +---------------------+----------+     |
  |  | System Groups    |  |     | Auto-Generated Groups          |     |
  |  | - system-super   |  |     | - AcmeIssuing-Admin    (lvl 1) |     |
  |  | - system-admin   |  |     | - AcmeIssuing-Operator (lvl 2) |     |
  |  | - system-operator|  |     | - AcmeIssuing-Auditor  (lvl 3) |     |
  |  | - system-auditor |  |     | - AcmeIssuing-User     (lvl 4) |     |
  |  +----+-------------+  |     +---------------------+----------+     |
  |       |                |                           |                |
  |  +----+--------+      |                    +-------+------+         |
  |  | Users       |      |                    | Users        |         |
  |  | - admin     |      |                    | - alice      |         |
  |  | - operator  |      |                    | - bob        |         |
  |  +-------------+      |                    +--------------+         |
  |                        |                                            |
  +----------------------------------------------------------------------+
`}</pre>
                </div>
            </section>

            {/* System Tenant */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">System Tenant</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    The system tenant is created automatically during setup and cannot be deleted. It owns the
                    root CA and the System Signing CA. System-level administrators belong to this tenant.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Always exists -- created during bootstrap</li>
                    <li>Owns the root CA hierarchy created during setup</li>
                    <li>Hosts system groups that grant cross-tenant access</li>
                    <li>The initial admin account belongs to the system tenant</li>
                    <li>Cannot be disabled or deleted</li>
                </ul>
                <div className="border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Note:</span> Users in the system tenant with appropriate
                        group roles can manage all other tenants. This is the platform-admin model.
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
                        via EF global query filter; system admins can
                        use <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">IgnoreQueryFilters()</code> to view</li>
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
                            <td className="py-2">When true, CA creation requires a multi-party key ceremony approval workflow</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">CeremonyRequiredApprovals</td>
                            <td className="py-2">Number of admin approvals needed before a ceremony can execute (default: 2)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">MaxCertificateAuthorities</td>
                            <td className="py-2">Maximum CAs allowed for this tenant (0 = unlimited)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">MaxCertificatesTotal</td>
                            <td className="py-2">Maximum total certificates across all CAs (0 = unlimited)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">MaxUsers</td>
                            <td className="py-2">Maximum user accounts in this tenant's groups (0 = unlimited)</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4 font-mono text-sm">IsSystemTenant</td>
                            <td className="py-2">System tenants cannot be deleted or disabled</td>
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
                    System-level groups use a <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-</code> prefix.
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
                    Resource quotas prevent any single tenant from consuming excessive resources. Quotas are
                    configured per tenant and enforced at issuance time.
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
                            <td className="py-2">Total number of active certificates per tenant</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Max CAs</td>
                            <td className="py-2">Number of Certificate Authorities per tenant</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Max Users</td>
                            <td className="py-2">Number of user accounts per tenant</td>
                        </tr>
                        <tr className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-4">Rate Limit</td>
                            <td className="py-2">Maximum certificate issuance rate (per hour/day)</td>
                        </tr>
                        <tr>
                            <td className="py-2 pr-4">Max Validity</td>
                            <td className="py-2">Maximum certificate validity period allowed</td>
                        </tr>
                    </tbody>
                </table>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Issuance Request
        |
        v
  +------------------+     +------------------+     +------------------+
  | Tenant Quota     |---->| CA Quota         |---->| Rate Limit       |
  | (total certs)    |     | (per-CA limit)   |     | (per-hour limit) |
  +--------+---------+     +--------+---------+     +--------+---------+
           |                        |                        |
      Pass | Fail             Pass  | Fail              Pass | Fail
           v                        v                        v
      Continue              429 Quota               429 Rate Limited
                            Exceeded
`}</pre>
                </div>
            </section>

            {/* Tenant Isolation */}
            <section className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-3">Tenant Isolation</h2>
                <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-3">
                    Tenant isolation is enforced at the application layer. All database queries are scoped
                    to the current tenant context, which is derived from the authenticated user's JWT claims.
                    Admin endpoints automatically filter results by tenant so users can only see CAs and
                    certificates within their own tenant scope.
                </p>
                <ul className="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300 mb-3">
                    <li>Every entity (CA, certificate, user, group) has a tenant ID foreign key</li>
                    <li>All queries include a tenant filter derived from the JWT <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">tenant</code> claim</li>
                    <li>Admin endpoints filter by tenant -- users only see CAs and certificates within their tenant</li>
                    <li>Cross-tenant access requires system-level groups (<code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-super</code>, <code className="text-sm bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded">system-admin</code>, etc.)</li>
                    <li>Audit logs are tenant-scoped (except for system-level events)</li>
                    <li>The tenant context switcher in the Admin UI allows system admins to view other tenants</li>
                </ul>
                <div className="bg-gray-100 dark:bg-gray-800 rounded p-4 font-mono text-sm overflow-x-auto mb-4">
                    <pre className="text-gray-700 dark:text-gray-300">{`
  Authenticated Request
        |
        v
  +---------------------+     +----------------------+     +---------------------+
  | Extract tenant      |---->| Tenant-scoped query  |---->| Return filtered     |
  | from JWT claim      |     | (WHERE TenantId = X) |     | results             |
  +---------------------+     +----------+-----------+     +---------------------+
                                         |
                               System group member?
                                    |          |
                                   Yes         No
                                    |          |
                                    v          v
                              All tenants   Own tenant
                              visible       only
`}</pre>
                </div>
                <div className="border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-r">
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        <span className="font-semibold">Important:</span> Tenant isolation is application-level,
                        not database-level. All tenants share the same database. The isolation is enforced by the
                        TenantContext middleware and query filters.
                    </p>
                </div>
            </section>
        </div>
    );
}
