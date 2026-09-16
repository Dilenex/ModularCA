import React, { createContext, useContext, useEffect, useState } from 'react';
import { apiGet, getToken } from '../api/client';
import { PORTAL } from '../portal';

interface TenantContextValue {
    tenants: any[];
    selectedTenantId: string;
    setSelectedTenantId: (id: string) => void;
    refreshTenants: () => void;
}

const TenantContext = createContext<TenantContextValue>({
    tenants: [],
    selectedTenantId: '',
    setSelectedTenantId: () => {},
    refreshTenants: () => {},
});

export const useTenant = () => useContext(TenantContext);

export const TenantProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [tenants, setTenants] = useState<any[]>([]);
    const [selectedTenantId, setSelectedTenantId] = useState(() =>
        localStorage.getItem('selectedTenant') || ''
    );

    const refreshTenants = () => {
        if (!getToken()) return; // Not authenticated — skip
        if (PORTAL !== 'admin') return; // The self-service portal has no tenant picker and its users cannot list tenants.
        apiGet<any>('/api/v1/admin/tenants')
            .then(data => setTenants(Array.isArray(data) ? data : data.items || []))
            .catch(() => {});
    };

    // Only fetch tenants when an auth token exists
    useEffect(() => {
        refreshTenants();
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        if (selectedTenantId) localStorage.setItem('selectedTenant', selectedTenantId);
        else localStorage.removeItem('selectedTenant');
    }, [selectedTenantId]);

    return (
        <TenantContext.Provider value={{ tenants, selectedTenantId, setSelectedTenantId, refreshTenants }}>
            {children}
        </TenantContext.Provider>
    );
};
