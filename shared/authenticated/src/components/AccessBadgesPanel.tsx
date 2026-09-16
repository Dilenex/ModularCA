import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useAuthClient } from '../api/AuthClientContext';
import { useToast } from '@shared/context/ToastContext';
import { AccessBadgeSourceKind, type AccessBadgeDto, type AccessBadgeSourceOptionDto, type AccessBadgeSourceRef } from '@shared/generated';

/**
 * Lists, creates, edits and deletes the access badges of one user.
 *
 * Used twice: on the account page for the signed-in user (`/api/v1/account/badges`) and on
 * an administrator's view of another user (`/api/v1/admin/users/{id}/badges`). Both endpoints
 * speak the same shapes, so the panel only needs the base path. A badge is built by ticking
 * grant sources the user holds; the server refuses anything else, so the list of sources here
 * is exactly the list of things a badge may be made of.
 */
export const AccessBadgesPanel: React.FC<{ basePath: string; embedded?: boolean }> = ({ basePath, embedded }) => {
    const { apiGet, apiPost, apiPut, apiDelete } = useAuthClient();
    const { showToast } = useToast();

    const [badges, setBadges] = useState<AccessBadgeDto[]>([]);
    const [sources, setSources] = useState<AccessBadgeSourceOptionDto[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [editing, setEditing] = useState<AccessBadgeDto | 'new' | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const [b, s] = await Promise.all([
                apiGet<AccessBadgeDto[]>(basePath),
                apiGet<AccessBadgeSourceOptionDto[]>(`${basePath}/sources`),
            ]);
            setBadges(Array.isArray(b) ? b : []);
            setSources(Array.isArray(s) ? s : []);
        } catch (e: any) {
            setError(e?.message || 'Failed to load badges');
        } finally {
            setLoading(false);
        }
    }, [apiGet, basePath]);

    useEffect(() => { load(); }, [load]);

    const remove = async (badge: AccessBadgeDto) => {
        if (!window.confirm(`Delete the badge "${badge.name}"? Any session wearing it goes badgeless at its next refresh.`)) return;
        try {
            await apiDelete(`${basePath}/${badge.id}`);
            showToast('success', `Badge "${badge.name}" deleted`);
            await load();
        } catch (e: any) {
            showToast('error', e?.message || 'Failed to delete badge');
        }
    };

    return (
        <div className={embedded ? 'space-y-4' : 'space-y-4'}>
            {!embedded && (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    A badge is a named subset of the rights this account already holds. Wearing one narrows what
                    a session may do and see; wearing none is the normal state. Badges are put on and taken off
                    from the sidebar.
                </p>
            )}

            {error && <div className="text-sm text-red-700 dark:text-red-400">{error}</div>}
            {loading && <div className="text-sm text-gray-500">Loading…</div>}

            {!loading && badges.length === 0 && editing === null && (
                <div className="text-sm text-gray-500 dark:text-gray-400">No badges yet.</div>
            )}

            <ul className="space-y-2">
                {badges.map((b) => (
                    <li key={b.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                        <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-sm font-semibold text-gray-900 dark:text-white">{b.name}</span>
                                    {b.isDefault && (
                                        <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300">default</span>
                                    )}
                                </div>
                                {b.description && <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">{b.description}</p>}
                                <ul className="mt-2 flex flex-wrap gap-1">
                                    {b.sources.map((s) => (
                                        <li key={`${s.kind}-${s.sourceId}`} className="text-[11px] px-1.5 py-0.5 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300" title={sourceTitle(s.kind)}>
                                            {s.label ?? <span className="italic text-gray-500">removed source</span>}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                            <div className="flex gap-2 flex-shrink-0">
                                <button onClick={() => setEditing(b)} className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Edit</button>
                                <button onClick={() => remove(b)} className="text-xs px-2 py-1 rounded border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30">Delete</button>
                            </div>
                        </div>
                    </li>
                ))}
            </ul>

            {editing === null ? (
                <button
                    onClick={() => setEditing('new')}
                    disabled={sources.length === 0}
                    title={sources.length === 0 ? 'This account holds no grant sources to build a badge from' : undefined}
                    className="text-sm px-3 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
                >
                    New badge
                </button>
            ) : (
                <BadgeForm
                    key={editing === 'new' ? 'new' : editing.id}
                    badge={editing === 'new' ? null : editing}
                    sources={sources}
                    onCancel={() => setEditing(null)}
                    onSave={async (body) => {
                        try {
                            if (editing === 'new') await apiPost(basePath, body);
                            else await apiPut(`${basePath}/${editing.id}`, body);
                            showToast('success', editing === 'new' ? 'Badge created' : 'Badge updated');
                            setEditing(null);
                            await load();
                        } catch (e: any) {
                            showToast('error', e?.message || 'Failed to save badge');
                        }
                    }}
                />
            )}
        </div>
    );
};

function sourceTitle(kind: AccessBadgeSourceKind): string {
    switch (kind) {
        case AccessBadgeSourceKind.Group: return 'Group membership';
        case AccessBadgeSourceKind.RoleAssignment: return 'Role assigned directly';
        case AccessBadgeSourceKind.CapabilityGrant: return 'Capability granted directly';
        default: return 'Grant source';
    }
}

interface WriteBody {
    name: string;
    description: string | null;
    isDefault: boolean;
    sources: AccessBadgeSourceRef[];
}

const BadgeForm: React.FC<{
    badge: AccessBadgeDto | null;
    sources: AccessBadgeSourceOptionDto[];
    onSave: (body: WriteBody) => Promise<void>;
    onCancel: () => void;
}> = ({ badge, sources, onSave, onCancel }) => {
    const [name, setName] = useState(badge?.name ?? '');
    const [description, setDescription] = useState(badge?.description ?? '');
    const [isDefault, setIsDefault] = useState(badge?.isDefault ?? false);
    const [picked, setPicked] = useState<Set<string>>(() => new Set((badge?.sources ?? []).map((s) => `${s.kind}:${s.sourceId}`)));
    const [saving, setSaving] = useState(false);

    const keyOf = (s: { kind: AccessBadgeSourceKind; sourceId: string }) => `${s.kind}:${s.sourceId}`;
    const toggle = (key: string) => setPicked((p) => { const n = new Set(p); if (n.has(key)) n.delete(key); else n.add(key); return n; });

    /** The union of capabilities the ticked sources contribute: what wearing this badge allows. */
    const preview = useMemo(() => {
        const caps = new Set<string>();
        for (const s of sources) if (picked.has(keyOf(s))) for (const c of s.capabilities) caps.add(c);
        return [...caps].sort();
    }, [sources, picked]);

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        try {
            await onSave({
                name: name.trim(),
                description: description.trim() || null,
                isDefault,
                sources: sources.filter((s) => picked.has(keyOf(s))).map((s) => ({ kind: s.kind, sourceId: s.sourceId })),
            });
        } finally {
            setSaving(false);
        }
    };

    const input = 'w-full px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';

    return (
        <form onSubmit={submit} className="bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-4">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{badge ? `Edit "${badge.name}"` : 'New badge'}</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label htmlFor="badge-name" className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                    <input id="badge-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} className={input} placeholder="e.g. Auditor on staging-ca-r1" />
                </div>
                <div>
                    <label htmlFor="badge-description" className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Description (optional)</label>
                    <input id="badge-description" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} className={input} />
                </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                <input id="badge-default" type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
                Start new sessions wearing this badge
            </label>

            <div>
                <div className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Grant sources to keep</div>
                <ul className="space-y-1 max-h-64 overflow-y-auto pr-1">
                    {sources.map((s) => {
                        const key = keyOf(s);
                        return (
                            <li key={key}>
                                <label className="flex items-start gap-2 text-sm text-gray-800 dark:text-gray-200 cursor-pointer">
                                    <input type="checkbox" className="mt-1" checked={picked.has(key)} onChange={() => toggle(key)} />
                                    <span className="min-w-0">
                                        <span className="font-medium">{s.label}</span>
                                        <span className="text-xs text-gray-500 dark:text-gray-400"> · {s.scope} · {sourceTitle(s.kind)}</span>
                                        {s.capabilities.length > 0 && (
                                            <span className="block text-[11px] text-gray-500 dark:text-gray-400 truncate">{s.capabilities.join(', ')}</span>
                                        )}
                                    </span>
                                </label>
                            </li>
                        );
                    })}
                </ul>
            </div>

            <div className="text-xs text-gray-600 dark:text-gray-400">
                {preview.length === 0
                    ? 'Nothing ticked: this badge would grant nothing.'
                    : <>Wearing it allows: <span className="font-mono">{preview.join(', ')}</span></>}
            </div>

            <div className="flex gap-2">
                <button type="submit" disabled={saving || picked.size === 0 || !name.trim()} className="text-sm px-3 py-1.5 rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">
                    {saving ? 'Saving…' : 'Save'}
                </button>
                <button type="button" onClick={onCancel} className="text-sm px-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">Cancel</button>
            </div>
        </form>
    );
};
