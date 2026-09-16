import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet } from '../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DetailPage, DetailSection } from '../components/DetailPage';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const TYPES = new Set(['general', 'est', 'scep', 'cmp', 'acme', 'msae', 'network']);
// Keys rendered with their own formatting / not in the generic dump.
const TIMESTAMP_KEYS = new Set(['timestamp']);

function auditTitle(type: string, log: any): string {
    if (type === 'network') return `${log.httpMethod || ''} ${log.requestPath || ''}`.trim() || 'Network event';
    if (type === 'general') return log.actionType || 'Audit entry';
    return log.operation || log.messageType || `${type.toUpperCase()} event`;
}

function auditStatus(type: string, log: any): React.ReactNode {
    if (type === 'network') {
        if (log.blocked) return <StatusBadge status="revoked" label="BLOCKED" />;
        if (log.statusCode >= 400) return <StatusBadge status="expired" label={`${log.statusCode}`} />;
        return <StatusBadge status="active" label={`${log.statusCode ?? 'OK'}`} />;
    }
    return <StatusBadge status={log.success ? 'active' : 'revoked'} label={log.success ? 'OK' : 'FAIL'} />;
}

/// <summary>
/// Read-only detail page for a single audit log entry. The audit table family is keyed by type
/// (general / est / scep / cmp / acme / network), carried in the route, so the page hits the matching
/// by-id endpoint. Audit entries are immutable, so the page is View-only (Edit disabled).
/// </summary>
const AuditLogDetail: React.FC = () => {
    const { type = 'general', id } = useParams<{ type: string; id: string }>();
    const navigate = useNavigate();

    const [log, setLog] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        if (!TYPES.has(type)) { setError(`Unknown audit type "${type}".`); setLoading(false); return; }
        let cancelled = false;
        setLoading(true);
        setError(null);
        const path = type === 'general' ? `/api/v1/admin/audit/${id}` : `/api/v1/admin/audit/${type}/${id}`;
        apiGet<any>(path)
            .then((data) => { if (!cancelled) { setLog(data); setLoading(false); } })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load audit entry')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [type, id]);

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <InlineNotice notice={error} variant="line" />
            <button onClick={() => navigate('/audit')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Audit Logs</button>
        </div>
    );
    if (!log) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Audit entry not found.</p>
            <button onClick={() => navigate('/audit')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Audit Logs</button>
        </div>
    );

    const typeLabel = type === 'general' ? 'General' : type.toUpperCase();
    // Dump every populated field; DetailField hides null/empty. Render objects as JSON.
    const entries = Object.entries(log).filter(([k]) => !TIMESTAMP_KEYS.has(k.toLowerCase()));

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Audit Logs', to: '/audit' }, { label: typeLabel }, { label: auditTitle(type, log) }]}
            title={auditTitle(type, log)}
            status={auditStatus(type, log)}
            subtitle={<><StatusBadge status="pending" label={typeLabel} /> <span className="ml-2">{formatDate(log.timestamp)}</span></>}
            backTo="/audit"
        >
            {() => (
                <DetailSection title="Audit Entry">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Timestamp" value={formatDate(log.timestamp)} />
                        {entries.map(([k, v]) => (
                            <DetailField
                                key={k}
                                label={k}
                                value={v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v))}
                                mono={typeof v === 'object' || /id$|serial|hash|ip$/i.test(k)}
                            />
                        ))}
                    </div>
                </DetailSection>
            )}
        </DetailPage>
    );
};

export default AuditLogDetail;
