import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { actionButton, actionButtonPrimary } from '@shared/components/actionButtons';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { Capabilities, StepUpOps } from '@shared/generated';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { useAuth } from '../context/AuthContext';
import ConfirmModal from './ConfirmModal';
import {
    RENEWAL_MAX_YEARS, RENEWAL_MIN_YEARS, hasRsaBelow3072, historyBadge, historyFileName, isRootCa, originLabel, renewalCannotExtend, renewalEffects, renewalMinimumYears, renewalUnavailable,
    renewalYearsProblem, validityNotes, type CaCertificateHistoryRow,
} from '../pages/caRenewal';

function day(value: string | null | undefined): string {
    if (!value) return '-';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? '-' : parsed.toISOString().slice(0, 10);
}

function downloadPem(pem: string, filename: string) {
    const url = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/// <summary>
/// The certificates a CA has had, and the action that gives it a new one over the same key.
/// The history lists the current certificate and every earlier one, each downloadable. Renewal
/// says what stays and what changes before it asks for confirmation and step-up; where the CA's
/// scope requires a key ceremony it opens one and links to it.
/// </summary>
const CaCertificateRenewal: React.FC<{ ca: any; onRenewed: () => void }> = ({ ca, onRenewed }) => {
    const { requireStepUp } = useStepUp();
    const { can } = useAuth();

    const [rows, setRows] = useState<CaCertificateHistoryRow[] | null>(null);
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [open, setOpen] = useState(false);
    const [years, setYears] = useState<number | ''>(isRootCa(ca) ? 20 : 10);
    const [confirming, setConfirming] = useState(false);
    // The warnings the administrator has read and accepts, by reason; sent with the renewal.
    const [acknowledged, setAcknowledged] = useState<string[]>([]);
    const [renewing, setRenewing] = useState(false);
    const [result, setResult] = useState<any | null>(null);
    const [error, setError] = useState<NoticeInput | null>(null);

    const load = useCallback(() => {
        apiGet<CaCertificateHistoryRow[]>(`/api/v1/admin/authorities/${ca.id}/certificates`, { toast: false })
            .then((data) => { setRows(Array.isArray(data) ? data : []); setLoadError(null); })
            .catch((err) => setLoadError(errorNotice(err, 'Failed to load the CA\'s certificates')));
    }, [ca.id]);

    useEffect(() => { load(); }, [load]);

    const unavailable = renewalUnavailable(ca) ?? renewalCannotExtend(ca);
    const minimumYears = renewalMinimumYears(ca);
    const mayRenew = can(Capabilities.CaManage, ca.id);
    const effects = renewalEffects(ca);
    const yearsProblem = renewalYearsProblem(years)
        ?? (typeof years === 'number' && years < minimumYears
            ? `The current certificate has more than ${years} year${years === 1 ? '' : 's'} left. Ask for at least ${minimumYears}, so that the new certificate ends after it.`
            : null);
    const root = isRootCa(ca);
    const notes = yearsProblem ? [] : validityNotes(root, years, hasRsaBelow3072(ca));
    const unacknowledged = notes.filter((n) => n.severity === 'warning' && !acknowledged.includes(n.reason));
    const renew = async () => {
        setConfirming(false);
        setRenewing(true);
        setResult(null);
        setError(null);
        try {
            const res = await apiPostWithMfa<any>(
                `/api/v1/admin/authorities/${ca.id}/renew-certificate`,
                { validityYears: years, acknowledge: acknowledged },
                requireStepUp,
                StepUpOps.RenewCaCertificate,
                ca.id,
            );
            setResult(res);
            if (!res?.requiresCeremony) {
                setOpen(false);
                load();
                onRenewed();
            }
        } catch (err: any) {
            // Cancelling the step-up prompt is a choice, not a failure to report.
            if (err?.message !== 'Step-up MFA cancelled') setError(errorNotice(err, 'The certificate was not renewed'));
        } finally {
            setRenewing(false);
        }
    };

    const columns: DataTableColumn<CaCertificateHistoryRow>[] = [
        { key: 'serial', header: 'Serial', defaultWidth: 300, minWidth: 160, exportValue: (r) => r.serialNumber, render: (r) => <span className="data-mono text-ink">{r.serialNumber}</span> },
        { key: 'status', header: 'Status', defaultWidth: 170, truncate: false, exportValue: (r) => historyBadge(r).label, render: (r) => { const b = historyBadge(r); return <StatusBadge status={b.status} label={b.label} />; } },
        { key: 'notBefore', header: 'Valid from', defaultWidth: 120, exportValue: (r) => day(r.notBefore), render: (r) => <span className="text-ink-muted">{day(r.notBefore)}</span> },
        { key: 'notAfter', header: 'Valid until', defaultWidth: 120, exportValue: (r) => day(r.notAfter), render: (r) => <span className="text-ink">{day(r.notAfter)}</span> },
        { key: 'origin', header: 'How', defaultWidth: 170, exportValue: (r) => originLabel(r.origin), render: (r) => <span className="text-ink-muted">{originLabel(r.origin)}{r.actor ? ` by ${r.actor}` : ''}</span> },
        {
            key: 'download', header: 'Certificate', flex: true, truncate: false, exportValue: () => '', render: (r) => (
                <span className="flex flex-wrap items-center gap-2">
                    {r.pem && <button type="button" className={actionButton} onClick={() => downloadPem(r.pem!, historyFileName(ca, r))}>Download PEM</button>}
                    <a className="text-xs text-accent-ink underline" href={`/ca/${encodeURIComponent(r.serialNumber)}`}>Public address</a>
                </span>
            ),
        },
    ];

    return (
        <div className="space-y-3">
            <p className="text-xs text-ink-muted max-w-3xl">
                Every certificate this CA has had over its key. A renewal adds one and leaves the earlier one valid until it expires:
                certificates issued under either validate under both, because they share one name and one key.
            </p>
            {loadError && <InlineNotice notice={loadError} />}
            {rows && (
                <DataTable<CaCertificateHistoryRow>
                    tableId="ca-certificate-history"
                    rows={rows}
                    rowKey={(r) => r.certificateId}
                    empty="No certificate"
                    disableExport
                    columns={columns}
                />
            )}

            {result?.requiresCeremony && (
                <div className="rounded border border-info/40 bg-info-soft p-3 max-w-3xl">
                    <p className="text-xs text-info">
                        {result.message} The new certificate will be valid until {day(result.notAfter)}
                        {result.shortenedToParent ? ', shortened to the parent CA\'s certificate' : ''}. Nothing changes until the ceremony is approved and executed.{' '}
                        <Link to="/ceremonies" className="underline">Open Key Ceremonies</Link>
                    </p>
                </div>
            )}
            {result && !result.requiresCeremony && (
                <div className="rounded border border-ok/40 bg-ok-soft p-3 max-w-3xl space-y-1">
                    <p className="text-xs text-ok">{result.message}</p>
                    <p className="text-ok data-mono">New serial: {result.serialNumber}</p>
                    {result.shortenedToParent && <p className="text-xs text-ok">The validity was shortened to end with the parent CA's certificate, on {day(result.notAfter)}.</p>}
                    {effects.after.map((line) => <p key={line} className="text-xs text-ink">{line}</p>)}
                </div>
            )}
            {error && <InlineNotice notice={error} />}

            {unavailable && <p className="text-xs text-ink-muted max-w-3xl">{unavailable}</p>}
            {!unavailable && mayRenew && !open && (
                <button type="button" className={actionButton} onClick={() => { setOpen(true); setResult(null); setError(null); }}>Renew certificate</button>
            )}

            {!unavailable && mayRenew && open && (
                <div className="space-y-3 max-w-3xl">
                    <div className="rounded border border-warn/40 bg-warn-soft p-3">
                        <p className="text-xs text-warn">
                            <strong>This gives the CA a new certificate over the key it already has.</strong> It is not undone by a later
                            action: the new certificate exists once it is signed, and every certificate issued from then on names it.
                            {root && ' A root\'s new certificate has to be given to everyone who trusts the old one, and this product cannot do that for you.'}
                        </p>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        <div>
                            <div className="font-semibold text-ink mb-1">Stays as it is</div>
                            <ul className="list-disc pl-5 space-y-1 text-ink-muted">{effects.stays.map((line) => <li key={line}>{line}</li>)}</ul>
                        </div>
                        <div>
                            <div className="font-semibold text-ink mb-1">Changes</div>
                            <ul className="list-disc pl-5 space-y-1 text-ink-muted">{effects.changes.map((line) => <li key={line}>{line}</li>)}</ul>
                            <div className="font-semibold text-ink mt-3 mb-1">Yours to do afterwards</div>
                            <ul className="list-disc pl-5 space-y-1 text-ink-muted">{effects.after.map((line) => <li key={line}>{line}</li>)}</ul>
                        </div>
                    </div>
                    <div className="max-w-xs">
                        <label className={labelClass} htmlFor="ca-renewal-years">New validity (years from today)</label>
                        <input id="ca-renewal-years" type="text" inputMode="numeric" className={inputClass} value={years}
                            onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); setYears(v === '' ? '' : parseInt(v, 10)); }} />
                        <FieldHint>
                            {yearsProblem
                                ?? (root
                                    ? `From ${RENEWAL_MIN_YEARS} to ${RENEWAL_MAX_YEARS}. The new certificate has to end after the current one.`
                                    : `From ${RENEWAL_MIN_YEARS} to ${RENEWAL_MAX_YEARS}. It is shortened to end with the parent CA's certificate when it would run past it.`)}
                        </FieldHint>
                    </div>
                    {notes.map((note) => note.severity === 'warning' ? (
                        <div key={note.reason} className="rounded border border-warn/40 bg-warn-soft p-3 space-y-2">
                            <p className="text-xs text-warn">{note.message}</p>
                            <label className="flex items-start gap-2 text-xs text-ink cursor-pointer">
                                <input type="checkbox" className="mt-0.5" checked={acknowledged.includes(note.reason)}
                                    onChange={(e) => setAcknowledged(e.target.checked ? [...acknowledged, note.reason] : acknowledged.filter((r) => r !== note.reason))} />
                                I have read this and want to renew the certificate with this validity.
                            </label>
                        </div>
                    ) : (
                        <p key={note.reason} className="text-xs text-ink-muted">{note.message}</p>
                    ))}
                    <p className="text-xs text-ink-muted">
                        Not offered here: a new key, a changed subject, a cross-certificate, or renewal on a schedule. A CA gets a new key only by creating a new CA.
                    </p>
                    <div className="flex items-center gap-2">
                        <button type="button" className={actionButtonPrimary} disabled={renewing || !!yearsProblem || unacknowledged.length > 0} onClick={() => setConfirming(true)}>
                            {renewing ? 'Renewing…' : 'Renew certificate'}
                        </button>
                        <button type="button" className={actionButton} disabled={renewing} onClick={() => setOpen(false)}>Cancel</button>
                    </div>
                </div>
            )}

            <ConfirmModal
                isOpen={confirming}
                title="Renew CA certificate"
                tone="warn"
                confirmLabel="Renew certificate"
                loading={renewing}
                message={(
                    <>
                        <p>Give &ldquo;{ca.name}&rdquo; a new certificate over its existing key, valid for {years} year{years === 1 ? '' : 's'}?</p>
                        <p className="mt-2">The key, the subject and every extension stay. The serial and the validity change. The earlier certificate stays valid and is not revoked.</p>
                        <p className="mt-2">If this CA's scope requires a key ceremony, this opens one and nothing changes until it is approved and executed.</p>
                    </>
                )}
                onConfirm={renew}
                onCancel={() => setConfirming(false)}
            />
        </div>
    );
};

export default CaCertificateRenewal;
