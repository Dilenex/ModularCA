import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Capabilities, StepUpOps } from '@shared/generated';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useStepUp } from './StepUpMfaContext';
import { auditTrailOutlivesEdge, continuityTitle, standingEvents, type ContinuityNotice } from './continuityNotice';

/// <summary>
/// The standing notice that this instance runs from an earlier or copied state: a snapshot was
/// rolled back, volumes were restored, or the machine was cloned, and the product was not told.
/// It stands above every page of the admin console for anyone who may read it (a system
/// auditor), until a system administrator acknowledges each event with step-up. It cannot be
/// dismissed any other way.
/// </summary>
const ContinuityNoticeBanner: React.FC = () => {
    const { can, loading } = useAuth();
    const { requireStepUp } = useStepUp();
    const [notice, setNotice] = useState<ContinuityNotice | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [busy, setBusy] = useState<string | null>(null);
    const [failed, setFailed] = useState<string | null>(null);

    const mayRead = !loading && can(Capabilities.AuditView);
    const mayAcknowledge = can(Capabilities.SystemManage);

    useEffect(() => {
        if (!mayRead) { setNotice(null); return; }
        let cancelled = false;
        apiGet<ContinuityNotice>('/api/v1/admin/continuity/notice', { toast: false })
            .then((data) => { if (!cancelled) setNotice(data && typeof data === 'object' ? data : null); })
            .catch(() => { if (!cancelled) setNotice(null); });
        return () => { cancelled = true; };
    }, [mayRead, refresh]);

    const events = standingEvents(notice);
    if (events.length === 0) return null;

    const acknowledge = async (id: string) => {
        setBusy(id); setFailed(null);
        try {
            await apiPostWithMfa(`/api/v1/admin/continuity/events/${id}/acknowledge`, undefined, requireStepUp, StepUpOps.AcknowledgeContinuityEvent, id);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            // Cancelling the step-up prompt is a deliberate choice, not a failure to report.
            if (err?.message !== 'Step-up MFA cancelled') setFailed(id);
        } finally {
            setBusy(null);
        }
    };

    return (
        <div role="alert" aria-label="This instance is running from an earlier or copied state"
            className="px-4 py-1.5 flex-shrink-0 bg-warn-soft border-b border-warn/40 text-xs text-warn space-y-1.5">
            {events.map((e) => (
                <div key={e.id} className="flex items-start justify-between gap-3">
                    <span>
                        <span className="font-semibold">{continuityTitle(e.kind)}</span>{' '}
                        {e.message}
                        {auditTrailOutlivesEdge(e) && (
                            <> The audit trail holds rows from after that time: <Link to="/audit" className="underline hover:no-underline">it may list what was issued and revoked since</Link>.</>
                        )}
                        {' '}A certificate from that time can be revoked from its CA's page, by its serial or by supplying the certificate.
                        {failed === e.id && <span className="font-semibold"> The acknowledgement was not recorded; try again.</span>}
                    </span>
                    {mayAcknowledge ? (
                        <button type="button" onClick={() => acknowledge(e.id)} disabled={busy !== null}
                            className="font-semibold underline hover:no-underline disabled:opacity-60 flex-shrink-0">
                            {busy === e.id ? 'Acknowledging…' : 'Acknowledge'}
                        </button>
                    ) : (
                        <span className="flex-shrink-0 opacity-80">A system administrator can acknowledge this.</span>
                    )}
                </div>
            ))}
        </div>
    );
};

export default ContinuityNoticeBanner;
