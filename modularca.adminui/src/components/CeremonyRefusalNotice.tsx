import React from 'react';
import { Link } from 'react-router-dom';
import { Capabilities } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { can } from '../authz';
import { type CeremonyRefusal, ceremonyRefusalAdvice, ceremonyRefusalLinks } from '../pages/ceremonyRefusal';

/**
 * Shown where an action was refused because the ceremony it needs could never be approved: what
 * the server said, what to do about it, and links to the steps this viewer can take.
 */
export const CeremonyRefusalNotice: React.FC<{ refusal: CeremonyRefusal; className?: string }> = ({ refusal, className = '' }) => {
    const { capabilities } = useAuth();
    const links = ceremonyRefusalLinks(refusal, {
        isSystemAdmin: can(capabilities, Capabilities.SystemManage),
        canManageUsers: can(capabilities, Capabilities.UserManage),
    });

    return (
        <div role="alert" className={`bg-warn-soft border border-warn/40 rounded p-3 space-y-2 ${className}`}>
            <p className="text-sm font-semibold text-warn">{refusal.detail}</p>
            <p className="text-xs text-warn">{ceremonyRefusalAdvice(refusal, links)}</p>
            {links.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                    {links.map((link) => (
                        <Link key={link.key} to={link.to}
                            className="px-3 py-1.5 text-xs font-medium bg-raised text-ink border border-line-strong rounded hover:bg-hover transition-colors">
                            {link.label}
                        </Link>
                    ))}
                </div>
            )}
            <p className="text-[11px] text-warn data-mono">{refusal.code}</p>
        </div>
    );
};

export default CeremonyRefusalNotice;
