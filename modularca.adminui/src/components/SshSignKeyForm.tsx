import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useStepUp } from './StepUpMfaContext';
import { StepUpOps } from '@shared/generated';
import { FieldHint, inputClass, inputClassNarrow, labelClass } from '@shared/components/forms';
import { ChipListInput } from '@shared/components/ChipListInput';
import { actionButton, actionButtonPrimary } from '@shared/components/actionButtons';
import { LoginNameTicks } from './SshCertificateParts';
import {
    defaultValidity, jsonList, serviceKeyId, serviceLabelError, validityLimit, validityLimitText, validityProblem,
    type SshHeldLoginName,
} from '../pages/sshLoginNames';
import { certificateTypeFor, defaultSignFor, keySignsFor, profilesForCertificateType, type SshSignFor } from '../pages/sshProfileType';
import { sshCaKeyPath } from '../pages/sshPlaces';

/** What the Sign key form hands back: the API's answer and who the certificate is for. */
export interface SshSignResult {
    id: string;
    keyId: string;
    serialNumber: number | string;
    signedCertificate: string;
    validAfter: string;
    validBefore: string;
    certType: 'user' | 'host';
    /** The user the certificate was signed for, when it was for one. */
    forUser: string | null;
    publicKey: string;
}

const STEP_UP_CANCELLED = 'Step-up MFA cancelled';

/// <summary>
/// The Sign key form, on the SSH tab of Request Certificate. It asks first who the certificate
/// is for: a user of this console, whose login names are offered as a tick list, a service
/// identity with a label and typed login names, or a host, which takes hostnames. Only the
/// request and certificate profiles of the matching type, or of no type, are then offered. The
/// CA writes the name hosts log, so the form shows it and asks for none. Signing asks step-up MFA.
/// </summary>
export const SshSignKeyForm: React.FC<{
    caKey: { id: string; name: string; isUserCa?: boolean; isHostCa?: boolean; maxValidityHours?: number };
    signBlocked: string | null;
    signingProfiles: any[];
    certProfiles: any[];
    requestProfiles: any[];
    onSigned: (result: SshSignResult) => void;
    onCancel: () => void;
}> = ({ caKey, signBlocked, signingProfiles, certProfiles, requestProfiles, onSigned, onCancel }) => {
    const { user: me } = useAuth();
    const { requireStepUp } = useStepUp();
    const [signFor, setSignFor] = useState<SshSignFor>(defaultSignFor(caKey));
    const certType = certificateTypeFor(signFor);
    const subject = signFor === 'service' ? 'service' : 'user';
    const [requestProfileId, setRequestProfileId] = useState('');
    const [signingProfileId, setSigningProfileId] = useState('');
    const [certProfileId, setCertProfileId] = useState('');
    const [users, setUsers] = useState<any[]>([]);
    const [subjectUserId, setSubjectUserId] = useState('');
    const [serviceLabel, setServiceLabel] = useState('');
    const [held, setHeld] = useState<SshHeldLoginName[] | null>(null);
    const [heldState, setHeldState] = useState<'idle' | 'loading' | 'refused' | 'failed'>('idle');
    /** False when the chosen user holds no right to request from this SSH CA, so nothing is signed for them. */
    const [mayRequest, setMayRequest] = useState(true);
    const [ticked, setTicked] = useState<string[]>([]);
    const [typed, setTyped] = useState<string[]>([]);
    const [publicKey, setPublicKey] = useState('');
    /** Null while the field follows the most allowed. */
    const [validity, setValidity] = useState<string | null>(null);
    const [signing, setSigning] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        let cancelled = false;
        apiGet<any>('/api/v1/admin/users', { toast: false })
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : (data?.items || data?.users || []);
                setUsers(list.filter((u: any) => u.isActive !== false).sort((a: any, b: any) => String(a.username).localeCompare(String(b.username))));
            })
            .catch(() => {});
        return () => { cancelled = true; };
    }, []);

    const forUser = certType === 'user' && subject === 'user';

    useEffect(() => {
        setHeld(null);
        setTicked([]);
        setValidity(null);
        setMayRequest(true);
        if (!forUser || !subjectUserId) { setHeldState('idle'); return; }
        let cancelled = false;
        setHeldState('loading');
        apiGet<any>(`/api/v1/admin/ssh/ca-keys/${caKey.id}/users/${subjectUserId}/login-names`, { toast: false })
            .then((data) => {
                if (cancelled) return;
                const names: SshHeldLoginName[] = Array.isArray(data?.loginNames) ? data.loginNames : [];
                setHeld(names);
                setMayRequest(data?.mayRequest !== false);
                setHeldState('idle');
            })
            .catch((err) => { if (!cancelled) setHeldState(err?.problem?.status === 404 ? 'refused' : 'failed'); });
        return () => { cancelled = true; };
    }, [forUser, subjectUserId, caKey.id]);

    // A profile whose type is the other one is refused by the sign routes, so it is not offered.
    const requestChoices = profilesForCertificateType(requestProfiles, certType);
    const requestProfile = requestChoices.find((p) => p.id === requestProfileId);
    const allowedSigning = useMemo(() => new Set(jsonList(requestProfile?.allowedSshSigningProfileIds)), [requestProfile]);
    const allowedCert = useMemo(() => new Set(jsonList(requestProfile?.allowedSshCertProfileIds)), [requestProfile]);
    const signingChoices = signingProfiles.filter((p) => p.sshCaKeyId === caKey.id
        && (allowedSigning.size === 0 || allowedSigning.has(p.id))
        && (certType === 'user' ? p.allowUserCerts : p.allowHostCerts));
    const certChoices = profilesForCertificateType(certProfiles, certType).filter((p) => allowedCert.size === 0 || allowedCert.has(p.id));

    /** Answers who the certificate is for. A change of certificate type starts the profiles over. */
    const chooseSignFor = (next: SshSignFor) => {
        if (certificateTypeFor(next) !== certType) {
            setRequestProfileId('');
            setSigningProfileId('');
            setCertProfileId('');
            setTyped([]);
        }
        setSignFor(next);
        setValidity(null);
    };
    const signingProfile = signingChoices.find((p) => p.id === signingProfileId);
    const certProfile = certChoices.find((p) => p.id === certProfileId);

    useEffect(() => {
        if (!requestProfileId) return;
        setSigningProfileId((cur) => (signingChoices.some((p) => p.id === cur) ? cur : (signingChoices[0]?.id ?? '')));
        setCertProfileId((cur) => (certChoices.some((p) => p.id === cur) ? cur : (certChoices[0]?.id ?? '')));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [requestProfileId, certType, caKey.id]);

    const profilesChosen = !!(requestProfile && signingProfile && certProfile);
    const ceiling = Math.min(
        requestProfile?.maxValidityHours ?? Infinity, signingProfile?.maxValidityHours ?? Infinity,
        certProfile?.maxValidityHours ?? Infinity, caKey.maxValidityHours ?? Infinity,
    );
    const patterns = useMemo(() => jsonList(certProfile?.allowedPrincipalPatterns), [certProfile]);
    const allowedByPatterns = (name: string): boolean =>
        patterns.length === 0 || patterns.some((p) => { try { return new RegExp(p).test(name); } catch { return false; } });
    const patternError = (name: string): string | null =>
        allowedByPatterns(name) ? null : `"${name}" matches none of the patterns of the certificate profile.`;

    const unavailable: Record<string, string> = {};
    for (const n of held ?? []) {
        if (!allowedByPatterns(n.name)) unavailable[n.name] = `Not allowed by the certificate profile ${certProfile?.name ?? ''}`.trim();
    }
    const tickedHeld = (held ?? []).filter((n) => ticked.includes(n.name) && !unavailable[n.name]);
    const names = forUser ? tickedHeld.map((n) => n.name) : typed;
    const limit = validityLimit(forUser ? tickedHeld : [], Number.isFinite(ceiling) ? ceiling : Number.MAX_SAFE_INTEGER, new Date());
    const validityShown = validity ?? (Number.isFinite(ceiling) ? defaultValidity(limit) : '');

    const what = certType === 'user' ? 'login name' : 'hostname';
    const problems: string[] = [];
    if (profilesChosen) {
        if (certProfile.maxPrincipals != null && names.length > certProfile.maxPrincipals) {
            problems.push(`${names.length} ${what}s are over the ${certProfile.maxPrincipals} the certificate profile allows on one certificate.`);
        }
        if (!forUser) for (const n of names) { const e = patternError(n); if (e) problems.push(e); }
        const v = validityProblem(validityShown, limit);
        if (v) problems.push(v);
        if (certType === 'user' && subject === 'service' && serviceLabel && serviceLabelError(serviceLabel)) problems.push(serviceLabelError(serviceLabel)!);
    }
    const subjectChosen = certType === 'host' || (subject === 'user' ? !!subjectUserId && heldState === 'idle' && !!held && mayRequest : !!serviceLabel);
    const ready = profilesChosen && subjectChosen && names.length > 0 && publicKey.trim() !== '' && problems.length === 0 && !signBlocked;

    const subjectUser = users.find((u) => u.id === subjectUserId);
    const loggedAs = certType === 'host' ? (typed[0] || '')
        : subject === 'user' ? (subjectUser?.username || '')
        : (serviceLabel && !serviceLabelError(serviceLabel) ? serviceKeyId(serviceLabel) : '');

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!ready) return;
        setSigning(true);
        setError(null);
        try {
            const body: Record<string, unknown> = { sshSigningProfileId: signingProfileId, sshCertProfileId: certProfileId, publicKey: publicKey.trim() };
            if (validityShown !== '') body.validityHours = Number(validityShown);
            if (certType === 'host') body.hostnames = names;
            else {
                body.principals = names;
                if (subject === 'user') body.subjectUserId = subjectUserId;
                else body.serviceLabel = serviceLabel;
            }
            const path = `/api/v1/admin/ssh/ca-keys/${caKey.id}/certificates/sign-${certType}`;
            const result: any = await apiPostWithMfa(path, body, requireStepUp, StepUpOps.SignSshCert, caKey.id);
            onSigned({ ...result, certType, forUser: forUser ? (subjectUser?.username ?? null) : null, publicKey: publicKey.trim() });
        } catch (err: any) {
            if (err?.message !== STEP_UP_CANCELLED) setError(errorNotice(err, 'Signing failed'));
        } finally {
            setSigning(false);
        }
    };

    const card = (kind: SshSignFor) => `max-w-3xl border rounded bg-raised p-3 space-y-2 ${signFor === kind ? 'border-accent' : 'border-line'}`;
    const limitText = forUser ? validityLimitText(limit) : null;

    return (
        <form onSubmit={submit} className="bg-raised border border-line rounded-lg p-4 space-y-4">
            <h3 className="text-sm font-semibold text-ink">Sign a {certType === 'user' ? 'user' : 'host'} key</h3>

            <div className="space-y-2" role="radiogroup" aria-labelledby="ssh-sign-for">
                <span id="ssh-sign-for" className={labelClass}>This certificate is for</span>
                {keySignsFor(caKey, 'user') && <div className={card('user')}>
                    <label htmlFor="ssh-sign-for-user" className="flex items-center gap-2 text-sm font-medium text-ink">
                        <input id="ssh-sign-for-user" type="radio" name="ssh-sign-for" checked={signFor === 'user'} onChange={() => chooseSignFor('user')} className="h-4 w-4 accent-accent" />
                        A user of this console
                    </label>
                    {signFor === 'user' && (
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pl-6">
                            <select aria-label="User" value={subjectUserId} onChange={(e) => setSubjectUserId(e.target.value)} className={`${inputClassNarrow} min-w-[14rem]`}>
                                <option value="">Choose a user…</option>
                                {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                            </select>
                            {subjectUser && (
                                <span className="text-xs text-ink-muted">
                                    Named <span className="font-mono text-ink">{subjectUser.username}</span> in host logs. The certificate appears under {subjectUser.username}'s own certificates, on the SSH tab of My Certificates.
                                </span>
                            )}
                        </div>
                    )}
                </div>}
                {keySignsFor(caKey, 'service') && <div className={card('service')}>
                    <label htmlFor="ssh-sign-for-service" className="flex items-center gap-2 text-sm font-medium text-ink">
                        <input id="ssh-sign-for-service" type="radio" name="ssh-sign-for" checked={signFor === 'service'} onChange={() => chooseSignFor('service')} className="h-4 w-4 accent-accent" />
                        A service identity with no account
                    </label>
                    <p className="pl-6 text-xs text-ink-muted">
                        You give it a label, and hosts log it as <span className="font-mono">svc:label</span>, which no username can equal. Its login names are typed and checked against the certificate profile.
                    </p>
                    {signFor === 'service' && (
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pl-6">
                            <input aria-label="Label" type="text" value={serviceLabel} onChange={(e) => setServiceLabel(e.target.value.trim())}
                                placeholder="e.g. backup-runner" autoComplete="off" spellCheck={false} className={`${inputClassNarrow} font-mono min-w-[14rem]`} />
                            <span className="text-xs text-ink-muted">
                                {serviceLabel && !serviceLabelError(serviceLabel)
                                    ? <>Named <span className="font-mono text-ink">{serviceKeyId(serviceLabel)}</span> in host logs.</>
                                    : 'A label is 1 to 64 letters, digits and . _ -'}
                            </span>
                        </div>
                    )}
                </div>}
                {keySignsFor(caKey, 'host') && <div className={card('host')}>
                    <label htmlFor="ssh-sign-for-host" className="flex items-center gap-2 text-sm font-medium text-ink">
                        <input id="ssh-sign-for-host" type="radio" name="ssh-sign-for" checked={signFor === 'host'} onChange={() => chooseSignFor('host')} className="h-4 w-4 accent-accent" />
                        A host
                    </label>
                    <p className="pl-6 text-xs text-ink-muted">
                        A host certificate, which a server presents to the clients that connect to it. It carries the server's hostnames.
                    </p>
                </div>}
                <FieldHint>Only the request and certificate profiles for a {certType} certificate, and those that serve either type, are offered below.</FieldHint>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                    <label htmlFor="ssh-sign-request" className={labelClass}>Request profile</label>
                    <select id="ssh-sign-request" required value={requestProfile ? requestProfileId : ''} className={inputClass}
                        onChange={(e) => { setRequestProfileId(e.target.value); setSigningProfileId(''); setCertProfileId(''); }}>
                        <option value="">Select request profile...</option>
                        {requestChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                    {requestChoices.length === 0 && <FieldHint tone="warn">There is no request profile for {certType} certificates. One is set up under Profiles, on the SSH Request tab.</FieldHint>}
                </div>
                <div>
                    <label htmlFor="ssh-sign-signing" className={labelClass}>Signing profile</label>
                    <select id="ssh-sign-signing" required disabled={!requestProfileId} value={signingProfileId} className={inputClass}
                        onChange={(e) => setSigningProfileId(e.target.value)}>
                        <option value="">Select signing profile...</option>
                        {signingChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                    {requestProfileId && signingChoices.length === 0 && (
                        <FieldHint tone="warn">This request profile allows no signing profile for {certType} certificates on this SSH CA.</FieldHint>
                    )}
                </div>
                <div>
                    <label htmlFor="ssh-sign-cert" className={labelClass}>Cert profile</label>
                    <select id="ssh-sign-cert" required disabled={!requestProfileId} value={certProfileId} className={inputClass}
                        onChange={(e) => setCertProfileId(e.target.value)}>
                        <option value="">Select cert profile...</option>
                        {certChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                    {requestProfileId && certChoices.length === 0 && <FieldHint tone="warn">This request profile allows no certificate profile.</FieldHint>}
                </div>
            </div>

            {profilesChosen && (
                <div className="p-2 bg-raised border border-line rounded text-xs text-ink-muted flex flex-wrap gap-x-4 gap-y-1">
                    <span>Longest certificate: <span className="text-ink font-medium">{Number.isFinite(ceiling) ? `${ceiling} h` : 'no limit'}</span></span>
                    <span>Most {what}s: <span className="text-ink font-medium">{certProfile.maxPrincipals}</span></span>
                    {signingProfile.forceCommand && <span>Force command: <span className="text-ink font-medium font-mono">{signingProfile.forceCommand}</span></span>}
                    {patterns.length > 0 && <span>{certType === 'user' ? 'Login name' : 'Hostname'} patterns: <span className="text-ink font-medium font-mono">{patterns.join(', ')}</span></span>}
                </div>
            )}

            <fieldset disabled={!profilesChosen} className={`space-y-4 min-w-0 ${profilesChosen ? '' : 'opacity-40'}`}>
                <div className="max-w-3xl">
                    <label htmlFor="ssh-sign-key" className={labelClass}>Public key</label>
                    <textarea id="ssh-sign-key" required rows={3} placeholder="ssh-ed25519 AAAA..." value={publicKey} onChange={(e) => setPublicKey(e.target.value)}
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono placeholder-ink-faint focus:outline-none focus:border-accent" />
                </div>

                {forUser && (
                    <div className="space-y-1.5">
                        <span className={labelClass}>Log in as</span>
                        {!subjectUserId && <p className="text-sm text-ink-muted">Choose the user first; their login names are listed here.</p>}
                        {heldState === 'loading' && <p className="text-sm text-ink-muted">Reading the login names…</p>}
                        {heldState === 'refused' && (
                            <FieldHint tone="warn">No certificate can be signed for this user with this SSH CA: the account is not active, or it has no role, group or grant on the SSH CA.</FieldHint>
                        )}
                        {heldState === 'failed' && <FieldHint tone="warn">The login names of this user could not be read. Choose the user again to retry.</FieldHint>}
                        {held && !mayRequest && (
                            <FieldHint tone="warn">{subjectUser?.username ?? 'This user'} may not request certificates from this SSH CA, so none can be signed for them. Give them a role on the SSH CA that lets them request first.</FieldHint>
                        )}
                        {held && mayRequest && held.length === 0 && (
                            <FieldHint tone="warn">{subjectUser?.username ?? 'This user'} holds no login name on this SSH CA: nothing is granted, and their own username does not count here. Own usernames are off, or the username is root or cannot be a login name.</FieldHint>
                        )}
                        {held && mayRequest && held.length > 0 && (
                            <LoginNameTicks idPrefix="ssh-sign-name" names={held} ticked={ticked} onChange={(next) => { setTicked(next); setValidity(null); }}
                                whose={subjectUser?.username ?? 'the user'} unavailable={unavailable} limitedBy={limit.loginName}
                                ceilingHours={Number.isFinite(ceiling) ? ceiling : undefined} />
                        )}
                        {subjectUserId && (
                            <FieldHint>
                                Only {subjectUser?.username ?? 'the user'}'s login names are offered, and nothing can be typed. To give {subjectUser?.username ?? 'the user'} another, <Link to={sshCaKeyPath(caKey.id)} className="text-accent-ink hover:underline">grant it on this CA</Link> first, so the grant is on record. A login name is the SSH principal: the account the certificate may log in as.
                            </FieldHint>
                        )}
                    </div>
                )}

                {!forUser && (
                    <div className="max-w-3xl">
                        <label htmlFor="ssh-sign-names" className={labelClass}>{certType === 'user' ? 'Log in as' : 'Hostnames'}</label>
                        <ChipListInput id="ssh-sign-names" value={typed} onChange={setTyped} validate={patternError} mono={certType === 'user'}
                            placeholder={certType === 'user' ? 'e.g. backup, then Enter' : 'e.g. web01.example.com, then Enter'}
                            invalid={profilesChosen && typed.length === 0} aria-describedby="ssh-sign-names-hint" />
                        <FieldHint id="ssh-sign-names-hint">
                            {certType === 'user'
                                ? 'The login names of the service identity: the accounts it may log in as. They are typed here and checked against the patterns of the certificate profile; no grant is needed. At least one is required. A login name is the SSH principal.'
                                : 'The names clients type to reach this host. At least one is required: a certificate with none would be valid for every host, and the signer refuses to issue one. The CA writes the first hostname as the name of this certificate in host logs.'}
                        </FieldHint>
                    </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-5 gap-y-3 max-w-3xl">
                    <div>
                        <label htmlFor="ssh-sign-hours" className={labelClass}>Valid for (hours)</label>
                        <input id="ssh-sign-hours" type="text" inputMode="numeric" value={validityShown}
                            onChange={(e) => setValidity(e.target.value.replace(/\D/g, ''))} className={`${inputClassNarrow} w-36`} />
                        <FieldHint>
                            {limitText ?? (Number.isFinite(ceiling)
                                ? `At most ${ceiling} hours, the smallest limit of the three profiles and the SSH CA. Leave empty for the most allowed.`
                                : 'Leave empty for the most allowed.')}
                        </FieldHint>
                    </div>
                    <div>
                        <span className={labelClass}>Recorded with the certificate</span>
                        <div className="px-3 py-2 border border-line rounded bg-sunken text-sm text-ink space-y-0.5">
                            <p>Issued to <span className="font-medium">{loggedAs || 'nobody yet'}</span>{certType === 'host' && loggedAs ? ', a host' : ''}</p>
                            <p>Issued by <span className="font-medium">{me?.username ?? 'you'}</span>{me?.username ? ' (you)' : ''}</p>
                            <p>Name in host logs <span className="font-mono font-medium">{loggedAs || '-'}</span></p>
                        </div>
                        <FieldHint>The CA writes the name in host logs; it cannot be typed or changed.</FieldHint>
                    </div>
                </div>
            </fieldset>

            {problems.length > 0 && (
                <div className="p-2 bg-crit-soft border border-crit/40 rounded text-xs text-crit space-y-0.5 max-w-3xl">
                    {problems.map((p) => <p key={p}>{p}</p>)}
                </div>
            )}
            <InlineNotice notice={error} onDismiss={() => setError(null)} />

            <div className="flex gap-2">
                <button type="submit" disabled={signing || !ready} className={actionButtonPrimary}>{signing ? 'Signing…' : 'Sign'}</button>
                <button type="button" onClick={onCancel} className={actionButton}>Clear</button>
            </div>
        </form>
    );
};
