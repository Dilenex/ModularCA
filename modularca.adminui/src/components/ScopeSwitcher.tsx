import React from 'react';
import { useAuth } from '../context/AuthContext';
import { useScope } from '../context/ScopeContext';
import { ALL_SCOPE, caScope, scopeLabel, withScope, type Scope } from '../scope';
import { PORTAL } from '../portal';

/**
 * The scope control in the top bar: one select, tenant and CA together.
 *
 * Options are grouped by tenant: each group offers the whole tenant ("All CAs") and then each
 * CA in it. Above the groups, "All tenants" for system-scoped callers; below them, "Mine",
 * which is the self-service portal. When the caller administers only one tenant the group
 * heading still names it, so the value reads as "where am I" at a glance. In the self-service
 * portal it shows "Mine" plus the way over to the console. Crossing between the portals is a
 * full navigation: they are the same bundle under different basenames, and the chosen scope
 * rides along in the query string.
 */
const MINE_VALUE = 'mine';
const ALL_VALUE = 'all';
const tenantValue = (id: string) => `tenant:${id}`;
const caValue = (id: string) => `ca:${id}`;

const ScopeSwitcher: React.FC = () => {
    const { canUseAdminConsole } = useAuth();
    const { scope, setScope, cas, tenants, canScopeToAll } = useScope();

    // A self-service user with no console rights has nothing to switch to.
    if (PORTAL === 'user' && !canUseAdminConsole) return null;
    if (PORTAL === 'admin' && cas.length === 0 && !canScopeToAll) return null;

    const value = scope.kind === 'ca' ? caValue(scope.caId)
        : scope.kind === 'tenant' ? tenantValue(scope.tenantId)
        : scope.kind === 'mine' ? MINE_VALUE
        : ALL_VALUE;

    const go = (next: Scope) => {
        if (next.kind === 'mine' && PORTAL !== 'user') {
            window.location.assign('/user/dashboard');
            return;
        }
        if (next.kind !== 'mine' && PORTAL !== 'admin') {
            window.location.assign(`/admin/dashboard?${withScope('', next).toString()}`);
            return;
        }
        setScope(next);
    };

    const choose = (raw: string) => {
        if (raw === MINE_VALUE) { go({ kind: 'mine' }); return; }
        if (raw === ALL_VALUE) { go(ALL_SCOPE); return; }
        if (raw.startsWith('tenant:')) {
            const t = tenants.find(x => x.id === raw.slice(7));
            if (t) go({ kind: 'tenant', tenantId: t.id, slug: t.slug, name: t.name });
            return;
        }
        if (raw.startsWith('ca:')) {
            const ca = cas.find(c => c.id === raw.slice(3));
            if (ca) go(caScope(ca));
        }
    };

    return (
        <label className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400 min-w-0" title={`Scope: ${scopeLabel(scope)}`}>
            <span className="hidden md:inline">Scope:</span>
            <select
                id="scope-switcher"
                aria-label="Scope"
                value={value}
                onChange={(e) => choose(e.target.value)}
                className="max-w-[16rem] px-2 py-1 text-xs rounded bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
            >
                {canScopeToAll && <option value={ALL_VALUE}>All tenants</option>}
                {tenants.map(t => (
                    <optgroup key={t.id} label={t.name}>
                        <option value={tenantValue(t.id)}>{t.name} · all CAs</option>
                        {cas.filter(c => c.tenantId === t.id).map(ca => (
                            <option key={ca.id} value={caValue(ca.id)}>{t.name} / {ca.label || ca.name}{ca.isSshCa ? ' (SSH)' : ''}</option>
                        ))}
                    </optgroup>
                ))}
                <option value={MINE_VALUE}>Mine (self-service)</option>
            </select>
        </label>
    );
};

export default ScopeSwitcher;
