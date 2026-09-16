import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiBlob } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import type { NoticeInput } from '@shared/notifications/notice';
import type { MsaeReadiness, MsaeReadinessStep } from '@shared/generated';
import { copyText } from '@shared/clipboard';
import { inputClass, labelClass } from '@shared/components/forms';

/**
 * Windows autoenrollment for one CA, as a checklist.
 *
 * The preconditions live on four pages with a dependency order the console never states; this
 * page asks the server for all of them at once (`/api/v1/admin/msae/{caId}/readiness`) and
 * shows each with its state and a link to the page that fixes it, scope preset. It changes
 * nothing itself. The readiness endpoint is the source of truth; the page only renders it.
 */

type State = MsaeReadinessStep['state'];

const STATE_STYLE: Record<string, { pill: string; label: string; ring: string }> = {
    Pass: { pill: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300', label: 'OK', ring: 'border-green-300 dark:border-green-800' },
    Warn: { pill: 'bg-amber-100 text-amber-900 dark:bg-amber-900/40 dark:text-amber-200', label: 'Check', ring: 'border-amber-300 dark:border-amber-800' },
    Fail: { pill: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300', label: 'Missing', ring: 'border-red-300 dark:border-red-800' },
    Skip: { pill: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400', label: 'Not yet', ring: 'border-gray-200 dark:border-gray-700' },
};

const Copy: React.FC<{ value: string; label: string }> = ({ value, label }) => {
    const [done, setDone] = useState(false);
    return (
        <button type="button" aria-label={`Copy ${label}`} onClick={async () => { if (await copyText(value)) { setDone(true); window.setTimeout(() => setDone(false), 1500); } }}
            className="px-1.5 py-0.5 text-[11px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">
            {done ? 'Copied' : 'Copy'}
        </button>
    );
};

const flattenCas = (cas: any[]): any[] => {
    const out: any[] = [];
    for (const ca of cas) {
        if ((ca.label || '').toLowerCase() !== 'system-signing-ca') out.push(ca);
        if (ca.children?.length) out.push(...flattenCas(ca.children));
    }
    return out;
};

const StepCard: React.FC<{ step: MsaeReadinessStep; index: number }> = ({ step, index }) => {
    const style = STATE_STYLE[step.state as string] ?? STATE_STYLE.Skip;
    return (
        <li className={`rounded-lg border ${style.ring} bg-white dark:bg-gray-800 p-4`}>
            <div className="flex items-start gap-3">
                <span className="mt-0.5 w-6 h-6 shrink-0 rounded-full bg-gray-200 dark:bg-gray-700 text-xs font-semibold flex items-center justify-center text-gray-700 dark:text-gray-200 tabular-nums">{index + 1}</span>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{step.title}</h3>
                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${style.pill}`}>{style.label}</span>
                    </div>
                    <p className="mt-1 text-sm text-gray-700 dark:text-gray-300">{step.detail}</p>
                    {step.items.length > 0 && (
                        <ul className="mt-2 space-y-1 text-xs text-gray-600 dark:text-gray-400">
                            {step.items.map((item, i) => {
                                const [head, ...rest] = item.includes(': ') ? item.split(': ') : [item];
                                const value = rest.join(': ');
                                const copyable = /^(Policy server URL|Policy id)$/.test(head);
                                return (
                                    <li key={i} className="flex items-start gap-2">
                                        <span className="break-words">
                                            {rest.length > 0 ? <><span className="font-medium text-gray-700 dark:text-gray-300">{head}:</span> <span className={copyable ? 'font-mono' : ''}>{value}</span></> : item}
                                        </span>
                                        {copyable && <Copy value={value} label={head} />}
                                    </li>
                                );
                            })}
                        </ul>
                    )}
                </div>
                {step.fix && (
                    <Link to={step.fix.path} className="shrink-0 px-3 py-1.5 text-xs font-semibold rounded bg-blue-600 text-white hover:bg-blue-700">{step.fix.label}</Link>
                )}
            </div>
        </li>
    );
};

const MsaeSetup: React.FC = () => {
    const { id } = useParams<{ id?: string }>();
    const navigate = useNavigate();
    const { scope } = useScope();
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [readiness, setReadiness] = useState<MsaeReadiness | null>(null);
    const [checking, setChecking] = useState(false);
    const [checkError, setCheckError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities/hierarchy')
            .then((data) => { setAuthorities(flattenCas(Array.isArray(data) ? data : (data.items || data.authorities || []))); setLoadError(null); })
            .catch((err) => setLoadError(errorNotice(err, 'Could not load the certificate authorities')));
    }, []);

    // Pick the CA: the route's, else the scoped one, else the first the operator can see.
    const selectedId = useMemo(() => {
        if (id) return id;
        if (scope.kind === 'ca' && scope.caId) return scope.caId;
        const inTenant = scope.kind === 'tenant' ? authorities.find((c) => c.tenantId === scope.tenantId) : null;
        return (inTenant ?? authorities[0])?.id ?? '';
    }, [id, scope, authorities]);

    useEffect(() => {
        if (!id && selectedId) navigate(`/authorities/windows/${selectedId}`, { replace: true });
    }, [id, selectedId, navigate]);

    const check = useCallback(() => {
        if (!selectedId) return;
        setChecking(true);
        apiGet<MsaeReadiness>(`/api/v1/admin/msae/${selectedId}/readiness`)
            .then((r) => { setReadiness(r); setCheckError(null); })
            .catch((err) => { setReadiness(null); setCheckError(errorNotice(err, 'Could not evaluate this CA')); })
            .finally(() => setChecking(false));
    }, [selectedId]);

    useEffect(() => { check(); }, [check]);

    const [kitBusy, setKitBusy] = useState<string | null>(null);
    const downloadKit = async (realmId: string, realmName: string) => {
        if (!readiness) return;
        setKitBusy(realmId);
        try {
            const blob = await (await apiBlob(`/api/v1/admin/msae/${readiness.caId}/setup-kit?realmId=${encodeURIComponent(realmId)}`)).blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `modularca-${readiness.caLabel}-${realmName.toLowerCase()}-setup.zip`;
            document.body.appendChild(a); a.click(); a.remove();
            URL.revokeObjectURL(url);
        } catch (err) {
            setCheckError(errorNotice(err, 'Could not build the setup kit'));
        } finally {
            setKitBusy(null);
        }
    };

    const failing = readiness?.steps.filter((s) => s.state === 'Fail').length ?? 0;
    const warning = readiness?.steps.filter((s) => s.state === 'Warn').length ?? 0;

    return (
        <div className="p-6 max-w-4xl space-y-5">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Windows Autoenrollment</h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Everything a domain-joined Windows machine needs before it can enroll from this CA on its own, in the order it has to be done. Each step links to the page that sets it.
                </p>
            </div>

            <InlineNotice notice={loadError} />

            <div className="flex items-end gap-3 flex-wrap">
                <div className="min-w-[16rem]">
                    <label className={labelClass} htmlFor="msae-setup-ca">Certificate authority</label>
                    <select id="msae-setup-ca" className={inputClass} value={selectedId} onChange={(e) => navigate(`/authorities/windows/${e.target.value}`)}>
                        {authorities.map((ca) => <option key={ca.id} value={ca.id}>{ca.name} ({ca.label})</option>)}
                    </select>
                </div>
                <button type="button" onClick={check} disabled={checking || !selectedId}
                    className="px-3 py-2 text-sm font-semibold rounded bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50">
                    {checking ? 'Checking…' : 'Check again'}
                </button>
                {readiness && <span className="text-xs text-gray-500 dark:text-gray-400 pb-2">Checked {new Date(readiness.evaluatedAt).toLocaleTimeString()}</span>}
            </div>

            <InlineNotice notice={checkError} />

            {readiness && (
                <>
                    <div className={`rounded-lg border px-4 py-3 ${readiness.ready ? 'border-green-300 dark:border-green-800 bg-green-50 dark:bg-green-900/20' : 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20'}`}>
                        <p className="text-sm font-semibold text-gray-900 dark:text-white">
                            {readiness.ready
                                ? `${readiness.caLabel} is ready for Windows autoenrollment${warning > 0 ? `, with ${warning} thing${warning === 1 ? '' : 's'} worth checking` : ''}.`
                                : `${readiness.caLabel} is not ready: ${failing} step${failing === 1 ? '' : 's'} still missing.`}
                        </p>
                        <div className="mt-2 grid gap-1 text-xs text-gray-700 dark:text-gray-300 sm:grid-cols-[auto_1fr_auto] items-center">
                            <span className="font-medium">Policy server URL</span>
                            <code className="font-mono break-all">{readiness.cepUrl}</code>
                            <Copy value={readiness.cepUrl} label="policy server URL" />
                            <span className="font-medium">Policy id</span>
                            <code className="font-mono break-all">{readiness.policyId}</code>
                            <Copy value={readiness.policyId} label="policy id" />
                        </div>
                    </div>

                    <ol className="space-y-3">
                        {readiness.steps.map((step, i) => <StepCard key={step.key} step={step} index={i} />)}
                    </ol>

                    {readiness.realms.length > 0 && (
                        <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-4">
                            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Setup kit for the customer's domain administrator</h2>
                            <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                                A zip with the service-account script, the Group Policy push for this policy server, the tenant root, a client self-check and a readme. It contains no secret: a generated account password was shown once at import and is not stored.
                            </p>
                            <ul className="mt-3 space-y-2">
                                {readiness.realms.map((r) => (
                                    <li key={r.id} className="flex items-center justify-between gap-3 flex-wrap text-sm">
                                        <span><span className="font-mono">{r.realm}</span> <span className="text-xs text-gray-500 dark:text-gray-400">({r.dnsDomain}, {r.servicePrincipal})</span></span>
                                        <button type="button" disabled={kitBusy !== null} onClick={() => downloadKit(r.id, r.realm)}
                                            className="px-3 py-1.5 text-xs font-semibold rounded bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50">
                                            {kitBusy === r.id ? 'Building…' : 'Download setup kit'}
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}

                    <p className="text-xs text-gray-500 dark:text-gray-400">
                        Once every step is green, run a policy refresh on a domain member and watch the MSAE tab under <Link to={`/audit?tab=MSAE${readiness.tenantId ? `&tenant=${readiness.tenantId}` : ''}&ca=${readiness.caId}`} className="text-blue-600 dark:text-blue-400 hover:underline">Audit Logs</Link>: an accepted ticket appears as an Enroll row, a refused one names its reason.
                    </p>
                </>
            )}
        </div>
    );
};

export default MsaeSetup;
