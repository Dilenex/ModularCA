import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { useAuth } from '../context/AuthContext';
import { Capabilities, StepUpOps } from '@shared/generated';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DataTable, type DataTableBulkAction, type DataTableColumn } from '@shared/components/DataTable';
import { NewButton } from '@shared/components/NewButton';
import { ChipListInput } from '@shared/components/ChipListInput';
import { FieldHint, ToggleField, inputClass, inputClassNarrow, labelClass } from '@shared/components/forms';
import { actionButton, actionButtonDanger, actionButtonPrimary } from '@shared/components/actionButtons';
import ConfirmModal from './ConfirmModal';
import { DetailSection } from './DetailPage';
import {
    LOGIN_NAMES_PER_GRANT, canOnSshCa, dateFieldValue, dayTimeText, existingGrants, grantEnd, grantTargetName, grantTermProblems, grantTermsBody,
    issuedByText, jsonList, loginNameError, longestCertificateText, removeGrantQuestion, revokeAllSentence, revokedSentence,
    type GrantTerms, type SshCertificateView, type SshLoginNameGrant, type SshLoginNameGrantList, type SshUserLoginName,
} from '../pages/sshLoginNames';
import { sshCaKeyPath, sshCertificatePath } from '../pages/sshPlaces';

const STEP_UP_CANCELLED = 'Step-up MFA cancelled';

/** Said once on each page that has login names. */
const WHAT_A_LOGIN_NAME_IS = 'A login name is the SSH principal: an account on the hosts, or a role name the hosts map to accounts.';

const loginNamesPath = (caKeyId: string) => `/api/v1/admin/ssh/ca-keys/${caKeyId}/login-names`;

const asList = (data: any, ...keys: string[]): any[] => {
    if (Array.isArray(data)) return data;
    for (const key of keys) if (Array.isArray(data?.[key])) return data[key];
    return [];
};

const GrantEndCell: React.FC<{ expiresAt?: string | null; ended?: boolean }> = ({ expiresAt, ended }) => {
    if (!expiresAt) return <span className="text-ink-muted">Never</span>;
    const end = grantEnd(expiresAt, new Date(), ended);
    return (
        <span className="inline-flex items-center gap-1.5">
            <span className="tabular-nums">{dayTimeText(expiresAt)}</span>
            {end.badge && <StatusBadge status={end.badge.status} label={end.badge.label} />}
        </span>
    );
};

const grantEndExport = (expiresAt?: string | null, ended?: boolean): string =>
    !expiresAt ? 'Never' : `${dayTimeText(expiresAt)}${ended ? ' (ended)' : ''}`;

const emptyTerms = (): GrantTerms => ({ hours: '', endDate: '', note: '' });

/* ── changing one grant ──────────────────────────────────────────────────── */

const GrantEditForm: React.FC<{
    grant: SshLoginNameGrant;
    keyMaxValidityHours: number;
    onSaved: () => void;
    onCancel: () => void;
}> = ({ grant, keyMaxValidityHours, onSaved, onCancel }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [terms, setTerms] = useState<GrantTerms>({
        hours: grant.maxValidityHours != null ? String(grant.maxValidityHours) : '',
        endDate: dateFieldValue(grant.expiresAt),
        note: grant.note || '',
    });
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const problems = grantTermProblems(terms, keyMaxValidityHours, new Date(), grant.expiresAt);
    const id = `ssh-grant-edit-${grant.id}`;

    const save = async (e: React.FormEvent) => {
        e.preventDefault();
        if (problems.length > 0) return;
        setBusy(true);
        setError(null);
        try {
            const result: any = await apiPutWithMfa(`${loginNamesPath(grant.sshCaKey.id)}/${grant.id}`, grantTermsBody(terms, grant.expiresAt),
                requireStepUp, StepUpOps.ManageSshLoginNames, grant.sshCaKey.id);
            showToast('success', `Grant changed. ${revokedSentence(result?.revokedCertificates ?? 0)}`);
            onSaved();
        } catch (err: any) {
            setError(errorNotice(err, 'The grant could not be changed.'));
        } finally {
            setBusy(false);
        }
    };

    return (
        <form onSubmit={save} className="bg-raised border border-line rounded-lg p-4 space-y-3">
            <h3 className="text-sm font-semibold text-ink">
                Change the grant of <span className="data-mono">{grant.loginName}</span> to {grantTargetName(grant)} on {grant.sshCaKey.name}
            </h3>
            {grant.ended && (
                <FieldHint tone="warn">This grant has ended and gives nothing now. Set a later end, or clear the end, to put it back in force.</FieldHint>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-3xl">
                <div>
                    <label htmlFor={`${id}-hours`} className={labelClass}>Longest certificate (hours)</label>
                    <input id={`${id}-hours`} type="text" inputMode="numeric" value={terms.hours}
                        onChange={(e) => setTerms({ ...terms, hours: e.target.value.replace(/\D/g, '') })} className={`${inputClassNarrow} w-36`} />
                    <FieldHint>Leave empty for the CA maximum, {keyMaxValidityHours} h. Lowering it revokes nothing: certificates already issued keep their validity.</FieldHint>
                </div>
                <div>
                    <label htmlFor={`${id}-end`} className={labelClass}>Grant ends (optional)</label>
                    <input id={`${id}-end`} type="date" value={terms.endDate} onChange={(e) => setTerms({ ...terms, endDate: e.target.value })} className={`${inputClassNarrow} w-48`} />
                    <FieldHint>Leave empty for no end. The grant ends at the end of this day. Moving the end earlier revokes the certificates that would outlive it.</FieldHint>
                </div>
            </div>
            <div className="max-w-3xl">
                <label htmlFor={`${id}-note`} className={labelClass}>Note (optional)</label>
                <input id={`${id}-note`} type="text" value={terms.note} onChange={(e) => setTerms({ ...terms, note: e.target.value })} className={inputClass} />
            </div>
            {problems.map((p) => <FieldHint key={p} tone="warn">{p}</FieldHint>)}
            <InlineNotice notice={error} onDismiss={() => setError(null)} />
            <div className="flex gap-2">
                <button type="submit" disabled={busy || problems.length > 0} className={actionButtonPrimary}>{busy ? 'Saving…' : 'Save'}</button>
                <button type="button" onClick={onCancel} className={actionButton}>Cancel</button>
            </div>
        </form>
    );
};

/* ── granting ────────────────────────────────────────────────────────────── */

interface KeyChoice { id: string; name: string }

/// <summary>
/// The "+ Grant" form: several login names at once, to one user or one group, on one SSH CA key.
/// A page fixes what it already knows (the key, the user or the group) and the form asks for the
/// rest. A name the target already has is said before anything is sent, with the way to its grant.
/// </summary>
const GrantForm: React.FC<{
    caKey?: KeyChoice;
    user?: { id: string; username: string };
    group?: { id: string; name: string };
    onGranted: () => void;
    onCancel: () => void;
    onEditExisting: (grant: SshLoginNameGrant, keyMaxValidityHours: number) => void;
}> = ({ caKey, user, group, onGranted, onCancel, onEditExisting }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const { capabilities } = useAuth();
    const uid = React.useId();

    const [keys, setKeys] = useState<KeyChoice[] | null>(caKey ? [caKey] : null);
    const [keyId, setKeyId] = useState(caKey?.id ?? '');
    const [list, setList] = useState<SshLoginNameGrantList | null>(null);
    const [targetKind, setTargetKind] = useState<'user' | 'group'>(group ? 'group' : 'user');
    const [users, setUsers] = useState<any[]>([]);
    const [groups, setGroups] = useState<any[]>([]);
    const [userId, setUserId] = useState(user?.id ?? '');
    const [groupId, setGroupId] = useState(group?.id ?? '');
    const [names, setNames] = useState<string[]>([]);
    const [terms, setTerms] = useState<GrantTerms>(emptyTerms());
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        if (caKey) return;
        let cancelled = false;
        apiGet<any>('/api/v1/admin/ssh/ca-keys', { toast: false })
            .then((data) => {
                if (cancelled) return;
                const mine = asList(data, 'items', 'keys')
                    .filter((k) => k.isUserCa && k.isEnabled !== false && canOnSshCa(capabilities, k, Capabilities.CaManage))
                    .map((k) => ({ id: k.id, name: k.name }));
                setKeys(mine);
                if (mine.length > 0) setKeyId(mine[0].id);
            })
            .catch(() => { if (!cancelled) setKeys([]); });
        return () => { cancelled = true; };
    }, [caKey, capabilities]);

    useEffect(() => {
        if (!keyId) { setList(null); return; }
        let cancelled = false;
        setList(null);
        apiGet<SshLoginNameGrantList>(loginNamesPath(keyId), { toast: false })
            .then((data) => { if (!cancelled) setList(data); })
            .catch(() => { if (!cancelled) setList(null); });
        return () => { cancelled = true; };
    }, [keyId]);

    useEffect(() => {
        if (user || group) return;
        let cancelled = false;
        apiGet<any>('/api/v1/admin/users', { toast: false })
            .then((data) => { if (!cancelled) setUsers(asList(data, 'items', 'users').filter((u) => u.isActive !== false)); })
            .catch(() => {});
        apiGet<any>('/api/v1/admin/groups', { toast: false })
            .then((data) => { if (!cancelled) setGroups(asList(data, 'items', 'groups').filter((g) => g.isInstance ?? g.spaceId == null)); })
            .catch(() => {});
        return () => { cancelled = true; };
    }, [user, group]);

    const target = targetKind === 'user' ? { userId: userId || null } : { groupId: groupId || null };
    const targetChosen = targetKind === 'user' ? !!userId : !!groupId;
    const keyMax = list?.maxValidityHours ?? null;
    const taken = list ? existingGrants(list.grants, names, target) : [];
    const badNames = names.filter((n) => loginNameError(n));
    const problems = keyMax != null ? grantTermProblems(terms, keyMax, new Date()) : [];
    if (names.length > LOGIN_NAMES_PER_GRANT) problems.unshift(`At most ${LOGIN_NAMES_PER_GRANT} login names can be granted at once.`);
    const ready = !!keyId && targetChosen && names.length > 0 && badNames.length === 0 && taken.length === 0 && problems.length === 0;

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!ready) return;
        setBusy(true);
        setError(null);
        try {
            const body = { loginNames: names, ...(targetKind === 'user' ? { userId } : { groupId }), ...grantTermsBody(terms) };
            const result: any = await apiPostWithMfa(loginNamesPath(keyId), body, requireStepUp, StepUpOps.ManageSshLoginNames, keyId);
            const made = Array.isArray(result?.grants) ? result.grants.length : names.length;
            showToast('success', `Granted ${made} login ${made === 1 ? 'name' : 'names'}.`);
            onGranted();
        } catch (err: any) {
            setError(errorNotice(err, 'The login names could not be granted.'));
        } finally {
            setBusy(false);
        }
    };

    if (keys && keys.length === 0) {
        return (
            <div className="bg-raised border border-line rounded-lg p-4 space-y-3">
                <p className="text-sm text-ink">There is no SSH CA to grant a login name on: none that signs user certificates is one you may manage.</p>
                <button type="button" onClick={onCancel} className={actionButton}>Close</button>
            </div>
        );
    }

    const segment = (kind: 'user' | 'group', label: string) => (
        <button type="button" aria-pressed={targetKind === kind} onClick={() => setTargetKind(kind)}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${targetKind === kind ? 'bg-accent-soft text-accent-ink' : 'bg-raised text-ink hover:bg-hover'}`}>
            {label}
        </button>
    );

    return (
        <form onSubmit={submit} className="bg-raised border border-line rounded-lg p-4 space-y-3">
            <h3 className="text-sm font-semibold text-ink">Grant login names</h3>
            {!caKey && (
                <div className="max-w-sm">
                    <label htmlFor={`${uid}-key`} className={labelClass}>SSH CA</label>
                    <select id={`${uid}-key`} value={keyId} onChange={(e) => setKeyId(e.target.value)} className={inputClass}>
                        {(keys ?? []).map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                    </select>
                    <FieldHint>Only the SSH CAs you may manage that sign user certificates are offered.</FieldHint>
                </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-5 gap-y-3 max-w-5xl">
                <div>
                    <label htmlFor={`${uid}-names`} className={labelClass}>Login names</label>
                    <ChipListInput id={`${uid}-names`} value={names} onChange={setNames} validate={loginNameError} mono
                        placeholder="e.g. deploy, then Enter" aria-describedby={`${uid}-names-hint`} />
                    <FieldHint id={`${uid}-names-hint`}>An account on the hosts, or a role name the hosts map to accounts. Type a name, then Enter; several can be granted at once. Upper and lower case are different names.</FieldHint>
                </div>
                <div>
                    <span id={`${uid}-to`} className={labelClass}>Grant to</span>
                    {user ? <p className="text-sm text-ink py-1.5">The user <span className="font-medium">{user.username}</span></p>
                        : group ? <p className="text-sm text-ink py-1.5">The group <span className="font-medium">{group.name}</span></p>
                        : (
                            <div role="group" aria-labelledby={`${uid}-to`} className="flex flex-wrap gap-2">
                                <div className="inline-flex rounded border border-line-strong overflow-hidden divide-x divide-line-strong">
                                    {segment('user', 'User')}
                                    {segment('group', 'Group')}
                                </div>
                                {targetKind === 'user' ? (
                                    <select aria-label="User" value={userId} onChange={(e) => setUserId(e.target.value)} className={`${inputClassNarrow} flex-1 min-w-[12rem]`}>
                                        <option value="">Choose a user…</option>
                                        {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                                    </select>
                                ) : (
                                    <select aria-label="Group" value={groupId} onChange={(e) => setGroupId(e.target.value)} className={`${inputClassNarrow} flex-1 min-w-[12rem]`}>
                                        <option value="">Choose a group…</option>
                                        {groups.map((g) => <option key={g.id} value={g.id}>{g.displayName || g.name} ({g.memberCount ?? 0} {g.memberCount === 1 ? 'member' : 'members'})</option>)}
                                    </select>
                                )}
                            </div>
                        )}
                    <FieldHint>
                        {targetKind === 'group'
                            ? 'Members get the name while they are in the group. Only instance groups are offered, because an SSH CA belongs to the instance.'
                            : 'The user needs a role, a group or a grant on this SSH CA first; a grant to anyone else is refused.'}
                    </FieldHint>
                </div>
                <div>
                    <label htmlFor={`${uid}-hours`} className={labelClass}>Longest certificate (hours)</label>
                    <input id={`${uid}-hours`} type="text" inputMode="numeric" value={terms.hours}
                        onChange={(e) => setTerms({ ...terms, hours: e.target.value.replace(/\D/g, '') })} className={`${inputClassNarrow} w-36`} />
                    <FieldHint>{keyMax != null ? `Leave empty for the CA maximum, ${keyMax} h.` : 'Leave empty for the CA maximum.'}</FieldHint>
                </div>
                <div>
                    <label htmlFor={`${uid}-end`} className={labelClass}>Grant ends (optional)</label>
                    <input id={`${uid}-end`} type="date" value={terms.endDate} onChange={(e) => setTerms({ ...terms, endDate: e.target.value })} className={`${inputClassNarrow} w-48`} />
                    <FieldHint>For temporary access. The grant ends at the end of this day, and no certificate outlives it.</FieldHint>
                </div>
            </div>
            <div className="max-w-3xl">
                <label htmlFor={`${uid}-note`} className={labelClass}>Note (optional)</label>
                <input id={`${uid}-note`} type="text" value={terms.note} onChange={(e) => setTerms({ ...terms, note: e.target.value })}
                    placeholder="e.g. Shared deploy account on the web tier" className={inputClass} />
            </div>

            {taken.map((g) => (
                <div key={g.id} role="status" className="bg-warn-soft border border-warn/40 rounded-md px-3 py-2 text-sm text-ink max-w-3xl flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span>
                        <span className="data-mono">{g.loginName}</span> is already granted to {grantTargetName(g)} on this SSH CA.
                        {g.ended && ' That grant has ended, but it still holds its place: the name cannot be granted again until the old grant is changed or removed.'}
                    </span>
                    <button type="button" onClick={() => onEditExisting(g, list!.maxValidityHours)} className={actionButton}>
                        {g.ended ? 'Edit the ended grant' : 'Edit that grant'}
                    </button>
                </div>
            ))}
            {problems.map((p) => <FieldHint key={p} tone="warn">{p}</FieldHint>)}
            <InlineNotice notice={error} onDismiss={() => setError(null)} />
            <div className="flex gap-2">
                <button type="submit" disabled={busy || !ready} className={actionButtonPrimary}>{busy ? 'Granting…' : 'Grant'}</button>
                <button type="button" onClick={onCancel} className={actionButton}>Cancel</button>
            </div>
        </form>
    );
};

/* ── what the three sections share ───────────────────────────────────────── */

/**
 * The grant form, the edit form and the removal of one grant, for a section that lists grants.
 * `reload` runs after every change.
 */
function useGrantChanges(reload: () => void) {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [granting, setGranting] = useState(false);
    const [editing, setEditing] = useState<{ grant: SshLoginNameGrant; keyMax: number } | null>(null);
    const [removing, setRemoving] = useState<SshLoginNameGrant | null>(null);
    const [busy, setBusy] = useState(false);

    const remove = async () => {
        if (!removing) return;
        setBusy(true);
        try {
            const result: any = await apiDeleteWithMfa(`${loginNamesPath(removing.sshCaKey.id)}/${removing.id}`,
                requireStepUp, StepUpOps.ManageSshLoginNames, removing.sshCaKey.id);
            showToast('success', `Grant removed. ${revokedSentence(result?.revokedCertificates ?? 0)}`);
            reload();
        } catch (err: any) {
            if (err?.message !== STEP_UP_CANCELLED) showToast('error', err?.message || 'The grant could not be removed.');
        } finally {
            setBusy(false);
            setRemoving(null);
        }
    };

    /** Reads the whole grant behind a row that carries only its id: its note, its own limit and its live certificates. */
    const resolve = async (caKeyId: string, grantId: string): Promise<{ grant: SshLoginNameGrant; keyMax: number } | null> => {
        try {
            const list = await apiGet<SshLoginNameGrantList>(loginNamesPath(caKeyId), { toast: false });
            const grant = list.grants.find((g) => g.id === grantId);
            if (grant) return { grant, keyMax: list.maxValidityHours };
            showToast('error', 'That grant is no longer there. The list has been reloaded.');
        } catch (err: any) {
            showToast('error', err?.message || 'The grant could not be read.');
        }
        reload();
        return null;
    };

    const modal = (
        <ConfirmModal
            isOpen={!!removing}
            title="Remove grant"
            message={removing ? removeGrantQuestion(removing) : ''}
            confirmLabel="Remove"
            tone="crit"
            loading={busy}
            onConfirm={remove}
            onCancel={() => setRemoving(null)}
        />
    );

    return {
        granting, editing, modal, resolve,
        openGrant: () => { setEditing(null); setGranting((g) => !g); },
        closeForms: () => { setGranting(false); setEditing(null); },
        edit: (grant: SshLoginNameGrant, keyMax: number) => { setGranting(false); setEditing({ grant, keyMax }); },
        askRemove: setRemoving,
        done: () => { setGranting(false); setEditing(null); reload(); },
    };
}

const liveColumn = <Row,>(live: (row: Row) => number): DataTableColumn<Row> => ({
    key: 'live', header: 'Live certificates', defaultWidth: 150, align: 'right',
    headerTitle: 'Unexpired, unrevoked certificates that carry the name under this grant.',
    exportValue: live, render: (r) => <span className="tabular-nums">{live(r)}</span>,
});

const LIVE_FOOTNOTE = 'Live certificates are the unexpired, unrevoked ones that carry the name under the grant. Removing a grant revokes them, unless their holder still has the name another way.';

/* ── on an SSH CA key's page ─────────────────────────────────────────────── */

/// <summary>
/// The Login names section of an SSH CA key's page: whether everyone may log in as their own
/// username, and the grants of login names to users and groups. Read-only without the right to
/// manage the SSH CA.
/// </summary>
export const SshKeyLoginNames: React.FC<{ caKey: { id: string; name: string; certificateAuthorityId?: string | null; isUserCa?: boolean; isEnabled?: boolean } }> = ({ caKey }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const { capabilities } = useAuth();
    const canManage = canOnSshCa(capabilities, caKey, Capabilities.CaManage) && caKey.isEnabled !== false;

    const [list, setList] = useState<SshLoginNameGrantList | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [switching, setSwitching] = useState(false);
    const changes = useGrantChanges(() => setRefresh((r) => r + 1));

    useEffect(() => {
        if (!caKey.isUserCa) { setLoading(false); return; }
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<SshLoginNameGrantList>(loginNamesPath(caKey.id), { toast: false })
            .then((data) => { if (!cancelled) { setList(data); setLoading(false); } })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'The login names could not be loaded.')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [caKey.id, caKey.isUserCa, refresh]);

    const setOwnUsername = async (allowed: boolean) => {
        setSwitching(true);
        try {
            const result: any = await apiPutWithMfa(`${loginNamesPath(caKey.id)}/own-username`, { allowed }, requireStepUp, StepUpOps.ManageSshLoginNames, caKey.id);
            showToast('success', allowed
                ? 'Everyone who can request from this SSH CA may now log in as their own username.'
                : `Own usernames are no longer login names on this SSH CA. ${revokedSentence(result?.revokedCertificates ?? 0)}`);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err?.message !== STEP_UP_CANCELLED) showToast('error', err?.message || 'The setting could not be changed.');
        } finally {
            setSwitching(false);
        }
    };

    const columns: DataTableColumn<SshLoginNameGrant>[] = useMemo(() => [
        { key: 'loginName', header: 'Login name', defaultWidth: 160, sortable: true, exportValue: (g) => g.loginName, render: (g) => <span className="data-mono">{g.loginName}</span> },
        {
            key: 'grantedTo', header: 'Granted to', defaultWidth: 280, truncate: false, sortable: true,
            sortValue: (g) => grantTargetName(g),
            exportValue: (g) => `${g.group ? 'Group' : 'User'}: ${grantTargetName(g)}`,
            render: (g) => (
                <span className="inline-flex items-center gap-2 min-w-0">
                    <Tag label={g.group ? 'Group' : 'User'} />
                    {g.group ? <Link to={`/groups/${g.group.id}`} className="text-accent-ink hover:underline truncate">{grantTargetName(g)}</Link>
                        : g.user?.id ? <Link to={`/users/${g.user.id}`} className="text-accent-ink hover:underline truncate">{grantTargetName(g)}</Link>
                        : <span className="text-ink-muted">{grantTargetName(g)}</span>}
                    {g.group && <span className="text-xs text-ink-muted whitespace-nowrap">{g.group.memberCount} {g.group.memberCount === 1 ? 'member' : 'members'}</span>}
                </span>
            ),
        },
        {
            key: 'longest', header: 'Longest certificate', defaultWidth: 160, exportValue: (g) => longestCertificateText(g.maxValidityHours),
            render: (g) => <span className={g.maxValidityHours != null ? 'tabular-nums' : 'text-ink-muted'}>{longestCertificateText(g.maxValidityHours)}</span>,
        },
        { key: 'ends', header: 'Grant ends', defaultWidth: 220, truncate: false, exportValue: (g) => grantEndExport(g.expiresAt, g.ended), render: (g) => <GrantEndCell expiresAt={g.expiresAt} ended={g.ended} /> },
        liveColumn<SshLoginNameGrant>((g) => g.liveCertificates),
        { key: 'grantedBy', header: 'Granted by', defaultWidth: 150, exportValue: (g) => g.grantedBy?.username || '', render: (g) => <span className="text-ink-muted">{g.grantedBy?.username || '-'}</span> },
        { key: 'note', header: 'Note', defaultWidth: 240, exportValue: (g) => g.note || '', render: (g) => <span className="text-ink-muted" title={g.note || undefined}>{g.note || ''}</span> },
    ], []);

    const bulkActions: DataTableBulkAction<SshLoginNameGrant>[] = [
        { label: 'Edit', single: true, onClick: (rows) => list && changes.edit(rows[0], list.maxValidityHours) },
        { label: 'Remove', single: true, variant: 'danger', onClick: (rows) => changes.askRemove(rows[0]) },
    ];

    if (!caKey.isUserCa) {
        return (
            <DetailSection title="Login names">
                <p className="text-sm text-ink-muted">This SSH CA signs no user certificates, so it has no login names. Host certificates carry hostnames, which are typed when a host key is signed.</p>
            </DetailSection>
        );
    }

    return (
        <DetailSection title="Login names">
            <div className="space-y-4">
                <p className="text-sm text-ink-muted max-w-3xl">
                    Who may get a certificate from this CA that logs in as which account. A request that names anything else is refused. {WHAT_A_LOGIN_NAME_IS}
                </p>
                {list && (
                    <div className="max-w-3xl">
                        <ToggleField
                            label="Everyone who can request from this CA may log in as their own username"
                            description="Needs no grant, except for root, which always does. Turn off where console usernames are not host accounts. It is saved at once, and turning it off revokes the live certificates that carry their holder's own username with no grant behind it."
                            checked={list.allowOwnUsername}
                            disabled={!canManage || switching}
                            onChange={setOwnUsername}
                        />
                    </div>
                )}
                {!canManage && (
                    <FieldHint>
                        {caKey.isEnabled === false
                            ? 'This SSH CA is disabled, so its login names can no longer be changed.'
                            : 'You can see these login names but not change them. Changing them takes the right to manage this SSH CA.'}
                    </FieldHint>
                )}

                {changes.granting && (
                    <GrantForm caKey={caKey} onGranted={changes.done} onCancel={changes.closeForms} onEditExisting={changes.edit} />
                )}
                {changes.editing && (
                    <GrantEditForm key={changes.editing.grant.id} grant={changes.editing.grant} keyMaxValidityHours={changes.editing.keyMax}
                        onSaved={changes.done} onCancel={changes.closeForms} />
                )}

                <DataTable<SshLoginNameGrant>
                    tableId="ssh-login-name-grants"
                    title="Grants"
                    findable
                    rows={list?.grants ?? []}
                    rowKey={(g) => g.id}
                    loading={loading}
                    error={error}
                    empty={list?.allowOwnUsername
                        ? 'No login names are granted. Everyone may still log in as their own username.'
                        : 'No login names are granted, and own usernames are off, so nobody can get a user certificate from this CA.'}
                    columns={columns}
                    selectable={canManage}
                    bulkActions={canManage ? bulkActions : undefined}
                    toolbarAction={canManage ? <NewButton label="Grant" what="login names" open={changes.granting} onClick={changes.openGrant} /> : undefined}
                    exportFileName={`ssh-login-names-${caKey.name}`}
                />
                <FieldHint>{LIVE_FOOTNOTE}</FieldHint>
                {changes.modal}
            </div>
        </DetailSection>
    );
};

/* ── on a user's page ────────────────────────────────────────────────────── */

const userRowKey = (r: SshUserLoginName) => `${r.sshCaKey.id}|${r.loginName}|${r.source}|${r.grantId ?? ''}`;

/// <summary>
/// The two SSH sections of a user's page: every login name the user holds, per SSH CA key and
/// with where it comes from, and the user's live SSH certificates with Revoke all. Only a name
/// granted to the user directly is changed here.
/// </summary>
export const SshUserLoginNames: React.FC<{ user: { id: string; username: string } }> = ({ user }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const { capabilities, canAnywhere } = useAuth();
    const canGrant = canAnywhere(Capabilities.CaManage);
    const canRevoke = canAnywhere(Capabilities.CertRevoke);

    const [names, setNames] = useState<SshUserLoginName[]>([]);
    const [certs, setCerts] = useState<SshCertificateView[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [certError, setCertError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [confirmRevoke, setConfirmRevoke] = useState(false);
    const [revoking, setRevoking] = useState(false);
    const changes = useGrantChanges(() => setRefresh((r) => r + 1));

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        setCertError(null);
        Promise.all([
            apiGet<any>(`/api/v1/admin/ssh/users/${user.id}/login-names`, { toast: false })
                .then((data) => { if (!cancelled) setNames(asList(data, 'loginNames')); })
                .catch((err) => { if (!cancelled) setError(errorNotice(err, 'The login names could not be loaded.')); }),
            apiGet<any>(`/api/v1/admin/ssh/users/${user.id}/certificates?live=true`, { toast: false })
                .then((data) => { if (!cancelled) setCerts(asList(data, 'items', 'certificates')); })
                .catch((err) => { if (!cancelled) setCertError(errorNotice(err, 'The certificates could not be loaded.')); }),
        ]).finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [user.id, refresh]);

    const mayChange = (r: SshUserLoginName) => r.source === 'user' && !!r.grantId && canOnSshCa(capabilities, r.sshCaKey, Capabilities.CaManage);

    const revokeAll = async () => {
        setRevoking(true);
        try {
            const result: any = await apiPostWithMfa(`/api/v1/admin/ssh/users/${user.id}/certificates/revoke`, {}, requireStepUp, StepUpOps.RevokeSshCert, user.id);
            const left = result?.leftForRights ?? 0;
            showToast(left > 0 ? 'info' : 'success', revokeAllSentence(result?.revoked ?? 0, left));
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err?.message !== STEP_UP_CANCELLED) showToast('error', err?.message || 'The certificates could not be revoked.');
        } finally {
            setRevoking(false);
            setConfirmRevoke(false);
        }
    };

    const nameColumns: DataTableColumn<SshUserLoginName>[] = useMemo(() => [
        { key: 'sshCa', header: 'SSH CA', defaultWidth: 180, sortable: true, exportValue: (r) => r.sshCaKey.name, render: (r) => <Link to={sshCaKeyPath(r.sshCaKey.id)} className="text-accent-ink hover:underline">{r.sshCaKey.name}</Link> },
        { key: 'loginName', header: 'Login name', defaultWidth: 150, sortable: true, exportValue: (r) => r.loginName, render: (r) => <span className="data-mono">{r.loginName}</span> },
        {
            key: 'source', header: 'Comes from', defaultWidth: 300, truncate: false,
            exportValue: (r) => (r.source === 'own' ? 'Own username' : r.source === 'group' ? `Group: ${r.groupName || ''}` : `Granted to ${user.username}`),
            render: (r) => (
                <span className="inline-flex items-center gap-2 min-w-0 flex-wrap">
                    {r.source === 'own' ? <span className="text-ink-muted">Own username</span>
                        : r.source === 'group' ? <><Tag label="Group" />{r.groupId ? <Link to={`/groups/${r.groupId}`} className="text-accent-ink hover:underline">{r.groupName || 'group'}</Link> : <span>{r.groupName}</span>}</>
                        : <><Tag label="User" /><span>Granted to {user.username}</span></>}
                    {!r.effective && <span className="text-xs text-ink-muted">a more generous ground counts</span>}
                </span>
            ),
        },
        {
            key: 'longest', header: 'Longest certificate', defaultWidth: 180,
            exportValue: (r) => (r.limitIsKeyMaximum ? longestCertificateText(null, r.maxValidityHours) : longestCertificateText(r.maxValidityHours)),
            render: (r) => r.limitIsKeyMaximum
                ? <span className="text-ink-muted">{longestCertificateText(null, r.maxValidityHours)}</span>
                : <span className="tabular-nums">{longestCertificateText(r.maxValidityHours)}</span>,
        },
        { key: 'ends', header: 'Grant ends', defaultWidth: 220, truncate: false, exportValue: (r) => grantEndExport(r.expiresAt), render: (r) => <GrantEndCell expiresAt={r.expiresAt} /> },
    ], [user.username]);

    const withGrant = async (row: SshUserLoginName, then: (found: { grant: SshLoginNameGrant; keyMax: number }) => void) => {
        const found = await changes.resolve(row.sshCaKey.id, row.grantId!);
        if (found) then(found);
    };
    const nameActions: DataTableBulkAction<SshUserLoginName>[] = [
        { label: 'Edit', single: true, onClick: (rows) => { void withGrant(rows[0], (f) => changes.edit(f.grant, f.keyMax)); } },
        { label: 'Remove', single: true, variant: 'danger', onClick: (rows) => { void withGrant(rows[0], (f) => changes.askRemove(f.grant)); } },
    ];

    const certColumns: DataTableColumn<SshCertificateView>[] = useMemo(() => [
        { key: 'serial', header: 'Serial', defaultWidth: 120, exportValue: (c) => String(c.serialNumber), render: (c) => <Link to={sshCertificatePath(c)} className="data-mono text-accent-ink hover:underline">{String(c.serialNumber)}</Link> },
        { key: 'sshCa', header: 'SSH CA', defaultWidth: 180, exportValue: (c) => c.sshCaKey?.name || '', render: (c) => <span>{c.sshCaKey?.name || '-'}</span> },
        { key: 'loginNames', header: 'Login names', defaultWidth: 240, exportValue: (c) => jsonList(c.principals).join(', '), render: (c) => <span className="data-mono">{jsonList(c.principals).join(', ')}</span> },
        { key: 'validBefore', header: 'Valid until', defaultWidth: 200, exportValue: (c) => dayTimeText(c.validBefore), render: (c) => <span className="tabular-nums">{dayTimeText(c.validBefore)}</span> },
        { key: 'issuedBy', header: 'Issued by', defaultWidth: 200, exportValue: (c) => issuedByText(c), render: (c) => <span className="text-ink-muted">{issuedByText(c)}</span> },
    ], []);

    return (<>
        <DetailSection title="SSH login names">
            <div className="space-y-4">
                <p className="text-sm text-ink-muted max-w-3xl">
                    Every account {user.username} may ask an SSH certificate for, and where each one comes from. {WHAT_A_LOGIN_NAME_IS}
                </p>
                {changes.granting && (
                    <GrantForm user={user} onGranted={changes.done} onCancel={changes.closeForms} onEditExisting={changes.edit} />
                )}
                {changes.editing && (
                    <GrantEditForm key={changes.editing.grant.id} grant={changes.editing.grant} keyMaxValidityHours={changes.editing.keyMax}
                        onSaved={changes.done} onCancel={changes.closeForms} />
                )}
                <DataTable<SshUserLoginName>
                    tableId="user-ssh-login-names"
                    title="Login names"
                    rows={names}
                    rowKey={userRowKey}
                    loading={loading}
                    error={error}
                    empty={`${user.username} holds no login name on any SSH CA you may view.`}
                    columns={nameColumns}
                    selectable={canGrant}
                    rowSelectable={mayChange}
                    bulkActions={canGrant ? nameActions : undefined}
                    toolbarAction={canGrant ? <NewButton label="Grant" what="login names" open={changes.granting} onClick={changes.openGrant} /> : undefined}
                    exportFileName={`ssh-login-names-${user.username}`}
                />
                <FieldHint>
                    Only names granted to {user.username} directly can be ticked here. A name that comes from a group is changed on the group, or on the SSH CA. A grant that has ended is not listed here; the SSH CA's own page shows it.
                </FieldHint>
                {changes.modal}
            </div>
        </DetailSection>

        <DetailSection title="Live SSH certificates">
            <div className="space-y-3">
                <DataTable<SshCertificateView>
                    tableId="user-ssh-certificates"
                    title="Certificates"
                    rows={certs}
                    rowKey={(c) => c.id}
                    loading={loading}
                    error={certError}
                    empty={`No live SSH certificate was issued for ${user.username} on an SSH CA you may view.`}
                    columns={certColumns}
                    toolbarAction={
                        <button type="button" onClick={() => setConfirmRevoke(true)} disabled={!canRevoke || certs.length === 0 || revoking}
                            title={!canRevoke ? 'Revoking takes the right to revoke on an SSH CA' : undefined} className={actionButtonDanger}>
                            Revoke all
                        </button>
                    }
                    exportFileName={`ssh-certificates-${user.username}`}
                />
                <FieldHint>
                    Disabling, renaming or deleting {user.username} revokes these and puts them in each SSH CA's revocation list. Certificates issued before login names were recorded are listed only where the upgrade could tell they were for {user.username}.
                </FieldHint>
                <ConfirmModal
                    isOpen={confirmRevoke}
                    title="Revoke all SSH certificates"
                    message={`Revoke every live SSH certificate of ${user.username}? ${certs.length} ${certs.length === 1 ? 'is' : 'are'} listed here. Only those on an SSH CA you may revoke on are revoked. A host refuses a revoked certificate once it has fetched the SSH CA's revocation list. This cannot be undone.`}
                    confirmLabel="Revoke all"
                    tone="crit"
                    loading={revoking}
                    onConfirm={revokeAll}
                    onCancel={() => setConfirmRevoke(false)}
                />
            </div>
        </DetailSection>
    </>);
};

/* ── on a group's page ───────────────────────────────────────────────────── */

/// <summary>
/// The SSH login names section of a group's page: what the group's members get, per SSH CA key.
/// An SSH CA belongs to the instance, so only an instance group can be granted a login name.
/// </summary>
export const SshGroupLoginNames: React.FC<{ group: { id: string; name: string; displayName?: string } }> = ({ group }) => {
    const { capabilities, canAnywhere } = useAuth();
    const [grants, setGrants] = useState<SshLoginNameGrant[]>([]);
    const [isInstance, setIsInstance] = useState<boolean | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const changes = useGrantChanges(() => setRefresh((r) => r + 1));
    const groupName = group.displayName || group.name;

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/ssh/groups/${group.id}/login-names`, { toast: false })
            .then((data) => { if (!cancelled) { setGrants(asList(data, 'grants')); setLoading(false); } })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'The login names could not be loaded.')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [group.id, refresh]);

    // The group's own record does not say whether it is an instance group; the list of groups does.
    useEffect(() => {
        let cancelled = false;
        apiGet<any>('/api/v1/admin/groups', { toast: false })
            .then((data) => {
                if (cancelled) return;
                const found = asList(data, 'items', 'groups').find((g) => g.id === group.id);
                setIsInstance(found ? (found.isInstance ?? found.spaceId == null) : null);
            })
            .catch(() => {});
        return () => { cancelled = true; };
    }, [group.id]);

    const mayChange = (g: SshLoginNameGrant) => canOnSshCa(capabilities, g.sshCaKey, Capabilities.CaManage);
    const canGrant = canAnywhere(Capabilities.CaManage) && isInstance !== false;

    const columns: DataTableColumn<SshLoginNameGrant>[] = useMemo(() => [
        { key: 'sshCa', header: 'SSH CA', defaultWidth: 180, sortable: true, exportValue: (g) => g.sshCaKey.name, render: (g) => <Link to={sshCaKeyPath(g.sshCaKey.id)} className="text-accent-ink hover:underline">{g.sshCaKey.name}</Link> },
        { key: 'loginName', header: 'Login name', defaultWidth: 160, sortable: true, exportValue: (g) => g.loginName, render: (g) => <span className="data-mono">{g.loginName}</span> },
        {
            key: 'longest', header: 'Longest certificate', defaultWidth: 160, exportValue: (g) => longestCertificateText(g.maxValidityHours),
            render: (g) => <span className={g.maxValidityHours != null ? 'tabular-nums' : 'text-ink-muted'}>{longestCertificateText(g.maxValidityHours)}</span>,
        },
        { key: 'ends', header: 'Grant ends', defaultWidth: 220, truncate: false, exportValue: (g) => grantEndExport(g.expiresAt, g.ended), render: (g) => <GrantEndCell expiresAt={g.expiresAt} ended={g.ended} /> },
        liveColumn<SshLoginNameGrant>((g) => g.liveCertificates),
        { key: 'grantedBy', header: 'Granted by', defaultWidth: 150, exportValue: (g) => g.grantedBy?.username || '', render: (g) => <span className="text-ink-muted">{g.grantedBy?.username || '-'}</span> },
        { key: 'note', header: 'Note', defaultWidth: 240, exportValue: (g) => g.note || '', render: (g) => <span className="text-ink-muted" title={g.note || undefined}>{g.note || ''}</span> },
    ], []);

    const withKeyMax = async (grant: SshLoginNameGrant) => {
        const found = await changes.resolve(grant.sshCaKey.id, grant.id);
        if (found) changes.edit(found.grant, found.keyMax);
    };
    const bulkActions: DataTableBulkAction<SshLoginNameGrant>[] = [
        { label: 'Edit', single: true, onClick: (rows) => { void withKeyMax(rows[0]); } },
        { label: 'Remove', single: true, variant: 'danger', onClick: (rows) => changes.askRemove(rows[0]) },
    ];

    return (
        <DetailSection title="SSH login names">
            <div className="space-y-4">
                <p className="text-sm text-ink-muted max-w-3xl">
                    What the members of {groupName} may ask an SSH certificate for, per SSH CA. A member holds these names while they are in the group; a member who leaves loses the certificates that carried a name only through it. {WHAT_A_LOGIN_NAME_IS}
                </p>
                {isInstance === false && (
                    <FieldHint>
                        Login names cannot be granted to this group. An SSH CA belongs to the instance, and only an instance group can be granted one of its login names; this group belongs to a space.
                    </FieldHint>
                )}
                {changes.granting && (
                    <GrantForm group={{ id: group.id, name: groupName }} onGranted={changes.done} onCancel={changes.closeForms} onEditExisting={changes.edit} />
                )}
                {changes.editing && (
                    <GrantEditForm key={changes.editing.grant.id} grant={changes.editing.grant} keyMaxValidityHours={changes.editing.keyMax}
                        onSaved={changes.done} onCancel={changes.closeForms} />
                )}
                <DataTable<SshLoginNameGrant>
                    tableId="group-ssh-login-names"
                    title="Login names"
                    rows={grants}
                    rowKey={(g) => g.id}
                    loading={loading}
                    error={error}
                    empty={`No login name is granted to ${groupName} on an SSH CA you may view.`}
                    columns={columns}
                    selectable={canGrant}
                    rowSelectable={mayChange}
                    bulkActions={canGrant ? bulkActions : undefined}
                    toolbarAction={canGrant ? <NewButton label="Grant" what="login names" open={changes.granting} onClick={changes.openGrant} /> : undefined}
                    exportFileName={`ssh-login-names-${group.name}`}
                />
                <FieldHint>{LIVE_FOOTNOTE}</FieldHint>
                {changes.modal}
            </div>
        </DetailSection>
    );
};
