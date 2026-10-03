import React from 'react';
import { useScope } from '../context/ScopeContext';
import { ALL_SCOPE, caScope, scopeLabel, type Scope } from '../scope';
import { PORTAL } from '../portal';

/**
 * The scope control in the top bar: one select, space and CA together.
 *
 * Options are grouped by space: each group offers the whole space ("all CAs") and then each
 * CA in it; above the groups, "All CAs" for system-scoped callers; below them, "Instance"
 * with the instance's own CAs (no space: the system signing CA, SSH CAs). When the caller
 * administers only one space the group heading still names it, so the value reads as "where
 * am I" at a glance. Only the console has a scope; the self-service portal is its own view,
 * reached through the portal switch beside this control.
 */
const ALL_VALUE = 'all';
const spaceValue = (id: string) => `space:${id}`;
const caValue = (id: string) => `ca:${id}`;

const ScopeSwitcher: React.FC = () => {
    const { scope, setScope, cas, spaces, canScopeToAll } = useScope();

    if (PORTAL !== 'admin') return null;
    if (cas.length === 0 && spaces.length === 0 && !canScopeToAll) return null;
    const instance = cas.filter(c => c.spaceId == null);

    const value = scope.kind === 'ca' ? caValue(scope.caId)
        : scope.kind === 'space' ? spaceValue(scope.spaceId)
        : ALL_VALUE;

    const go = (next: Scope) => setScope(next);

    const choose = (raw: string) => {
        if (raw === ALL_VALUE) { go(ALL_SCOPE); return; }
        if (raw.startsWith('space:')) {
            const t = spaces.find(x => x.id === raw.slice('space:'.length));
            if (t) go({ kind: 'space', spaceId: t.id, slug: t.slug, name: t.name });
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
                {canScopeToAll && <option value={ALL_VALUE}>All CAs</option>}
                {spaces.map(t => (
                    <optgroup key={t.id} label={t.name}>
                        <option value={spaceValue(t.id)}>{t.name} · all CAs</option>
                        {cas.filter(c => c.spaceId === t.id).map(ca => (
                            <option key={ca.id} value={caValue(ca.id)}>{t.name} / {ca.label || ca.name}{ca.isSshCa ? ' (SSH)' : ''}</option>
                        ))}
                    </optgroup>
                ))}
                {instance.length > 0 && (
                    <optgroup label="Instance">
                        {instance.map(ca => (
                            <option key={ca.id} value={caValue(ca.id)}>Instance / {ca.label || ca.name}{ca.isSshCa ? ' (SSH)' : ''}</option>
                        ))}
                    </optgroup>
                )}
            </select>
        </label>
    );
};

export default ScopeSwitcher;
