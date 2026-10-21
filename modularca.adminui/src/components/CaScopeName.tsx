import React from 'react';
import { useScope } from '../context/ScopeContext';

/** A profile's CA scope by the CA's name: the fallback when it has none, the id for a CA the viewer cannot see. */
export const CaScopeName: React.FC<{ caId?: string | null; fallback: string }> = ({ caId, fallback }) => {
    const { cas } = useScope();
    if (!caId) return <>{fallback}</>;
    const ca = cas.find((c) => c.id === caId);
    return ca ? <>{ca.name || ca.label}</> : <span className="data-mono break-all">{caId}</span>;
};
