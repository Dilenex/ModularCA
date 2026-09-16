import React from 'react';
import { useAuth } from '../context/AuthContext';
import { useScope } from '../context/ScopeContext';
import { ALL_SCOPE, scopeLabel, withScope, type Scope } from '../scope';
import { PORTAL } from '../portal';

/**
 * The CA scope control at the top of the sidebar.
 *
 * In the console it offers "All CAs" (to system-scoped callers), each CA the caller may
 * administer, and "Mine", which is the self-service portal. In the self-service portal it
 * shows "Mine" and, for a caller with console rights, the CAs that would open the console on
 * that CA. Crossing between the portals is a full navigation: they are the same bundle under
 * different basenames, and the chosen scope rides along in the query string.
 */
const MINE_VALUE = 'mine';
const ALL_VALUE = 'all';

const ScopeSwitcher: React.FC = () => {
    const { canUseAdminConsole } = useAuth();
    const { scope, setScope, cas, canScopeToAll } = useScope();

    // A self-service user with no console rights has nothing to switch to.
    if (PORTAL === 'user' && !canUseAdminConsole) return null;
    if (PORTAL === 'admin' && cas.length === 0 && !canScopeToAll) return null;

    const value = scope.kind === 'ca' ? scope.caId : scope.kind;

    const choose = (raw: string) => {
        let next: Scope;
        if (raw === MINE_VALUE) next = { kind: 'mine' };
        else if (raw === ALL_VALUE) next = ALL_SCOPE;
        else {
            const ca = cas.find(c => c.id === raw);
            if (!ca) return;
            next = { kind: 'ca', caId: ca.id, label: ca.label };
        }

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

    return (
        <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
            <label htmlFor="scope-switcher" className="block text-[10px] font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-1">
                Scope
            </label>
            <select
                id="scope-switcher"
                value={value}
                onChange={(e) => choose(e.target.value)}
                title={`Scope: ${scopeLabel(scope)}`}
                className="w-full px-2 py-1.5 text-xs rounded bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
            >
                {canScopeToAll && <option value={ALL_VALUE}>All CAs</option>}
                {cas.map(ca => (
                    <option key={ca.id} value={ca.id}>{ca.label || ca.name}{ca.isSshCa ? ' (SSH)' : ''}</option>
                ))}
                <option value={MINE_VALUE}>Mine (self-service)</option>
            </select>
        </div>
    );
};

export default ScopeSwitcher;
