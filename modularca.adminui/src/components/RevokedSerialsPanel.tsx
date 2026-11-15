import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import type { AdoptCertificateRequest, RecordRevokedSerialRequest } from '@shared/generated';
import { StepUpOps } from '@shared/generated';
import { InlineNotice } from '@shared/components/InlineNotice';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { actionButton, actionButtonDanger } from '@shared/components/actionButtons';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';
import { REVOCATION_REASONS, RevocationReasonHint } from '../pages/CertificateDetail';
import { adoptionBody, serialProblem, tombstoneBody, type RevokedSerialRow } from './revokedSerials';

/** The reasons a serial or an adopted certificate can be revoked with: every reason but the hold, which cannot be given here. */
const TOMBSTONE_REASONS = REVOCATION_REASONS.filter((r) => r.value !== 'CertificateHold');

function formatDate(d: string | null | undefined) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const field = 'w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:opacity-50';
const cancelButton = 'px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50';
const confirmDanger = 'px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors disabled:opacity-50';
const confirmPrimary = 'px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors disabled:opacity-50';

const columns: DataTableColumn<RevokedSerialRow>[] = [
    { key: 'serial', header: 'Serial', defaultWidth: 280, minWidth: 140, sortable: true, exportValue: (r) => r.serialNumber, render: (r) => <span className="data-mono text-ink break-all">{r.serialNumber}</span> },
    { key: 'reason', header: 'Reason', defaultWidth: 170, sortable: true, exportValue: (r) => r.reason, render: (r) => <span className="text-ink">{REVOCATION_REASONS.find((x) => x.value === r.reason)?.label ?? r.reason}</span> },
    { key: 'revoked', header: 'Revoked', defaultWidth: 170, sortable: true, sortValue: (r) => r.revocationDate, exportValue: (r) => r.revocationDate, render: (r) => <span className="text-ink-muted whitespace-nowrap">{formatDate(r.revocationDate)}</span> },
    { key: 'crl', header: 'On the CRL', defaultWidth: 210, truncate: false, sortable: true, sortValue: (r) => r.listedUntil, exportValue: (r) => r.listedUntil, render: (r) => (
        <span className="flex items-center gap-2 whitespace-nowrap">
            <StatusBadge status={r.onCrl ? 'revoked' : 'expired'} label={r.onCrl ? 'Listed' : 'Pruned'} />
            <span className="text-xs text-ink-muted">{r.onCrl ? 'until' : 'since'} {formatDate(r.listedUntil)}</span>
        </span>
    ) },
    { key: 'by', header: 'Recorded by', defaultWidth: 140, sortable: true, exportValue: (r) => r.recordedBy, render: (r) => <span className="text-ink-muted truncate">{r.recordedBy || '-'}</span> },
    { key: 'note', header: 'Note', flex: true, exportValue: (r) => r.note, render: (r) => <span className="text-ink-muted truncate" title={r.note}>{r.note}</span> },
];

/// <summary>
/// On a CA's page: revocation of certificates the CA does not hold. Lists the serials recorded as
/// revoked with no certificate behind them, and offers the two actions: record a serial, and adopt
/// a certificate supplied from outside. Shown only to a caller with cert.revoke on the CA; both
/// actions ask for step-up.
/// </summary>
const RevokedSerialsPanel: React.FC<{ caId: string; caName: string }> = ({ caId, caName }) => {
    const { requireStepUp } = useStepUp();
    const [rows, setRows] = useState<RevokedSerialRow[]>([]);
    const [loadError, setLoadError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [dialog, setDialog] = useState<'serial' | 'adopt' | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [done, setDone] = useState<React.ReactNode>(null);

    const [serial, setSerial] = useState('');
    const [reason, setReason] = useState('Unspecified');
    const [note, setNote] = useState('');
    const [certificate, setCertificate] = useState('');
    const [revokeOnAdopt, setRevokeOnAdopt] = useState(false);

    useEffect(() => {
        let cancelled = false;
        apiGet<RevokedSerialRow[]>(`/api/v1/admin/authorities/${caId}/revoked-serials`, { toast: false })
            .then((data) => { if (!cancelled) { setRows(Array.isArray(data) ? data : []); setLoadError(null); } })
            .catch((err) => { if (!cancelled) setLoadError(errorNotice(err, 'Failed to load the revoked serials')); });
        return () => { cancelled = true; };
    }, [caId, refresh]);

    const open = useCallback((which: 'serial' | 'adopt') => {
        setSerial(''); setReason('Unspecified'); setNote(''); setCertificate(''); setRevokeOnAdopt(false);
        setError(null); setDone(null); setDialog(which);
    }, []);

    const submit = async () => {
        setBusy(true); setError(null);
        try {
            if (dialog === 'serial') {
                const body: RecordRevokedSerialRequest = tombstoneBody(serial, reason, note);
                const res = await apiPostWithMfa<any>(`/api/v1/admin/authorities/${caId}/revoked-serials`, body, requireStepUp, StepUpOps.RevokeSerial, caId);
                setDone(<>Serial <span className="data-mono">{res.serialNumber}</span> is recorded as revoked{res.crlNumber ? <> and listed on CRL {res.crlNumber}</> : <>; the next CRL lists it</>}.</>);
            } else {
                const body: AdoptCertificateRequest = adoptionBody(certificate, note, revokeOnAdopt ? reason : null);
                const res = await apiPostWithMfa<any>(`/api/v1/admin/authorities/${caId}/adopted-certificates`, body, requireStepUp, StepUpOps.AdoptCertificate, caId);
                setDone(<>
                    Certificate <Link to={`/certificates/${res.serialNumber}`} className="underline data-mono">{res.serialNumber}</Link> is adopted
                    {res.revoked ? (res.fromTombstone ? ' and revoked, as its serial was already recorded.' : ' and revoked.') : '. It can be revoked from its own page.'}
                </>);
            }
            setDialog(null);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            // Cancelling the step-up prompt is a deliberate choice, not a failure to report.
            if (err?.message !== 'Step-up MFA cancelled') setError(errorNotice(err, dialog === 'serial' ? 'The serial was not recorded' : 'The certificate was not adopted'));
        } finally {
            setBusy(false);
        }
    };

    const serialIssue = dialog === 'serial' && serial.trim() ? serialProblem(serial) : null;
    const ready = note.trim().length > 0
        && (dialog === 'serial' ? serial.trim().length > 0 && !serialIssue : certificate.trim().length > 0);

    return (
        <div className="space-y-3">
            <p className="text-xs text-ink-muted max-w-3xl">
                For a certificate this CA signed that is not in its certificate list: one issued in time that a snapshot rollback
                or a restore took away, for example. Supplying the certificate is better, because it is verified under the CA's
                key and becomes an ordinary certificate with its own expiry. With only the serial, the serial itself is put on
                the CRL.
            </p>
            <div className="flex flex-wrap items-center gap-2">
                <button type="button" onClick={() => open('adopt')} className={actionButton}>Adopt a certificate</button>
                <button type="button" onClick={() => open('serial')} className={actionButtonDanger}>Revoke a serial</button>
            </div>

            {done && (
                <div className="rounded border border-ok/40 bg-ok-soft p-3 max-w-3xl">
                    <p className="text-xs text-ok">{done}</p>
                </div>
            )}
            {loadError && <InlineNotice notice={loadError} />}

            {rows.length > 0 && (
                <div className="overflow-x-auto">
                    <DataTable<RevokedSerialRow>
                        tableId="ca-revoked-serials"
                        rows={rows}
                        rowKey={(r) => r.id}
                        empty="No serial is recorded as revoked without its certificate"
                        columns={columns}
                    />
                </div>
            )}

            {dialog && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !busy && setDialog(null)}>
                    <div className="bg-raised border border-line rounded-lg shadow-xl w-full max-w-lg mx-4" role="dialog" aria-modal="true"
                        aria-label={dialog === 'serial' ? 'Revoke a serial' : 'Adopt a certificate'} onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-line">
                            <h2 className="text-lg font-semibold text-ink">{dialog === 'serial' ? 'Revoke a serial without its certificate' : 'Adopt a certificate'}</h2>
                        </div>
                        <div className="px-6 py-4 space-y-4">
                            <div className="space-y-1"><div className="text-xs text-ink-muted">Certificate authority</div><div className="text-sm text-ink break-all">{caName}</div></div>

                            {dialog === 'serial' ? (
                                <>
                                    <div className="space-y-1">
                                        <label htmlFor="tombstone-serial" className="block text-xs text-ink-muted">Serial number (hexadecimal)</label>
                                        <input id="tombstone-serial" value={serial} onChange={(e) => setSerial(e.target.value)} disabled={busy}
                                            autoComplete="off" spellCheck={false} placeholder="0A:1B:2C…" className={`${field} data-mono`} />
                                        {serialIssue && <p className="text-xs text-crit">{serialIssue}</p>}
                                    </div>
                                    <p className="text-xs text-ink-muted">
                                        The revocation is permanent, and nothing checks that this CA ever issued the serial. The entry stays on
                                        the CRL for the longest validity this CA's profiles allow, since the serial alone says nothing of when
                                        its certificate expires. If the CA holds a certificate with this serial, revoke that certificate instead.
                                    </p>
                                </>
                            ) : (
                                <>
                                    <div className="space-y-1">
                                        <label htmlFor="adopt-certificate" className="block text-xs text-ink-muted">Certificate (PEM, or base64 of its DER encoding)</label>
                                        <textarea id="adopt-certificate" value={certificate} onChange={(e) => setCertificate(e.target.value)} disabled={busy}
                                            rows={7} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" className={`${field} data-mono`} />
                                    </div>
                                    <p className="text-xs text-ink-muted">
                                        The certificate is adopted only if this CA's key signed it. It is then listed with the CA's other
                                        certificates, marked as adopted, with no known requester.
                                    </p>
                                    <label className="flex items-center gap-2 text-sm text-ink cursor-pointer">
                                        <input type="checkbox" checked={revokeOnAdopt} onChange={(e) => setRevokeOnAdopt(e.target.checked)} disabled={busy} />
                                        Revoke it in the same step
                                    </label>
                                </>
                            )}

                            {(dialog === 'serial' || revokeOnAdopt) && (
                                <div className="space-y-1">
                                    <label htmlFor="outside-reason" className="block text-xs text-ink-muted">Revocation Reason</label>
                                    <select id="outside-reason" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} className={field}>
                                        {TOMBSTONE_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                                    </select>
                                    <RevocationReasonHint reason={reason} />
                                </div>
                            )}

                            <div className="space-y-1">
                                <label htmlFor="outside-note" className="block text-xs text-ink-muted">
                                    {dialog === 'serial' ? 'Why is it revoked without its certificate?' : 'Where did the certificate come from?'}
                                </label>
                                <textarea id="outside-note" value={note} onChange={(e) => setNote(e.target.value)} disabled={busy} rows={2} maxLength={1000} className={field} />
                            </div>

                            {error && <InlineNotice notice={error} />}
                        </div>
                        <div className="px-6 py-4 border-t border-line flex justify-end gap-3">
                            <button type="button" onClick={() => setDialog(null)} disabled={busy} className={cancelButton}>Cancel</button>
                            <button type="button" onClick={submit} disabled={busy || !ready}
                                className={dialog === 'serial' || revokeOnAdopt ? confirmDanger : confirmPrimary}>
                                {busy ? 'Working…' : dialog === 'serial' ? 'Revoke serial' : revokeOnAdopt ? 'Adopt and revoke' : 'Adopt'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RevokedSerialsPanel;
