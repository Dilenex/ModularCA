import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiDeleteWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { isUnboundRequestProfile, mayChangeProfile } from './profiles/instanceWide';
import { NewProfileButton } from './profiles/NewProfileButton';

/* read-only drawer for a request profile row */
const RequestProfileDrawer: React.FC<{ profile: any; parentName: (id?: string | null) => string | undefined }> = ({ profile: p, parentName }) => (
    <div className="text-sm">
        <DetailField label="Name" value={p.name} />
        <DetailField label="Description" value={p.description} />
        <DetailField label="Require Approval" value={p.requireApproval ? 'Yes' : 'No'} />
        <DetailField label="Max Validity" value={p.maxValidityPeriod} />
        <DetailField label="Subject DN Rules" value={`${p.subjectDnRules?.length || 0} rule(s)`} />
        <DetailField label="SAN Required" value={p.sanRules?.required ? 'Yes' : 'No'} />
        {p.inheritanceEnabled && <DetailField label="Inherits From" value={parentName(p.inheritsFromId) || 'None'} />}
        <DetailField label="CA Scope" value={p.certificateAuthorityId ? String(p.certificateAuthorityId) : 'System-wide'} />
        <p className="text-[11px] text-ink-muted pt-3">Open the full page to view rules or edit.</p>
    </div>
);

/// <summary>
/// Request Profiles tab: a DataTable of enrollment request profiles. Creating one and row detail
/// and editing live on /profiles/request/new and /profiles/request/:id.
/// </summary>
const RequestProfiles: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const { can } = useAuth();
    const systemCertRevoke = can(Capabilities.CertRevoke);
    const [profiles, setProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirmDelete, setConfirmDelete] = useState<any | null>(null);
    const [deleting, setDeleting] = useState(false);

    const load = () => {
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/request-profiles')
            .then((data) => setProfiles(Array.isArray(data) ? data : (data.items || data.profiles || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
    }, []);

    const resolveParentName = (id: string | undefined | null) => {
        if (!id) return undefined;
        const p = profiles.find((pr) => pr.id === id);
        return p ? p.name : id;
    };

    const performDelete = async () => {
        if (!confirmDelete) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/request-profiles/${confirmDelete.id}`, requireStepUp, StepUpOps.DeleteRequestProfile, confirmDelete.id);
            showToast('success', 'Request profile deleted');
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete request profile');
        } finally {
            setDeleting(false);
            setConfirmDelete(null);
        }
    };

    const columns: DataTableColumn<any>[] = [
        {
            key: 'name', header: 'Name', defaultWidth: 240, minWidth: 160, truncate: false, exportValue: (p) => p.name,
            render: (p) => (
                <span className="flex items-center gap-2 min-w-0">
                    <span className="text-ink font-medium truncate">{p.name}</span>
                    {p.inheritanceEnabled && p.inheritsFromId && (
                        <span className="px-2 py-0.5 text-[10px] rounded bg-accent-soft text-accent-ink border border-accent/40 shrink-0">Inherits: {resolveParentName(p.inheritsFromId)}</span>
                    )}
                </span>
            ),
        },
        { key: 'approval', header: 'Approval', defaultWidth: 110, truncate: false, exportValue: (p) => (p.requireApproval ? 'Required' : 'Auto'), render: (p) => <Tag label={p.requireApproval ? 'Required' : 'Auto'} /> },
        { key: 'dnRules', header: 'DN Rules', defaultWidth: 100, exportValue: (p) => (p.subjectDnRules?.length || 0), render: (p) => <span className="text-xs text-ink">{p.subjectDnRules?.length || 0} rules</span> },
        { key: 'san', header: 'SAN', defaultWidth: 110, truncate: false, exportValue: (p) => (p.sanRules?.required ? 'Required' : 'Optional'), render: (p) => <Tag label={p.sanRules?.required ? 'Required' : 'Optional'} /> },
        { key: 'maxValidity', header: 'Max Validity', defaultWidth: 130, exportValue: (p) => p.maxValidityPeriod || '', render: (p) => <span className="text-xs text-ink-muted">{p.maxValidityPeriod || '-'}</span> },
    ];

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Delete', single: true, variant: 'danger', onClick: (rows) => setConfirmDelete(rows[0]), enabledFor: (p) => mayChangeProfile(isUnboundRequestProfile(p), systemCertRevoke) },
    ];

    return (
        <div className="space-y-4">
            <p className="text-sm text-ink-muted">
                Manage enrollment request profiles that define subject DN rules, SAN constraints, and approval requirements.
            </p>

            <DataTable<any>
                toolbarEnd={<NewProfileButton type="request" />}
                tableId="request-profiles"
                title="Request Profiles"
                findable
                rows={profiles}
                rowKey={(p) => p.id}
                loading={loading}
                error={error}
                empty="No request profiles found"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="request-profiles"
                renderDrawer={(p) => <RequestProfileDrawer profile={p} parentName={resolveParentName} />}
                drawerTitle={(p) => p.name}
                detailPath={(p) => `/profiles/request/${p.id}`}
            />

            <ConfirmModal
                isOpen={!!confirmDelete}
                title="Delete Request Profile"
                message={confirmDelete ? `Delete request profile "${confirmDelete.name}"? This cannot be undone.` : ''}
                confirmLabel="Delete"
                tone="crit"
                loading={deleting}
                onConfirm={performDelete}
                onCancel={() => setConfirmDelete(null)}
            />
        </div>
    );
};

export default RequestProfiles;
