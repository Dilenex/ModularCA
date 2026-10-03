import React from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export interface OrganizationData {
    orgName: string;
    orgDescription: string;
}

interface OrganizationProps {
    data: OrganizationData;
    onChange: (data: OrganizationData) => void;
}

const Organization: React.FC<OrganizationProps> = ({ data, onChange }) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Organization</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    Configure your organization details. The name is the Organization (O) field in your CA certificates and names your first space.
                </p>
            </div>

            <div className="space-y-4">
                <div>
                    <label htmlFor="orgName" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Organization Name <span className="text-red-500">*</span>
                    </label>
                    <input
                        ref={autoFocusRef}
                        id="orgName"
                        type="text"
                        required
                        value={data.orgName}
                        onChange={e => onChange({ ...data, orgName: e.target.value })}
                        placeholder="Contoso Ltd"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="orgDescription" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Description
                    </label>
                    <textarea
                        id="orgDescription"
                        value={data.orgDescription}
                        onChange={e => onChange({ ...data, orgDescription: e.target.value })}
                        placeholder="A brief description of your organization (optional)"
                        rows={3}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                    />
                </div>
            </div>

            {data.orgName.trim() && (
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                    <p className="text-sm text-blue-800 dark:text-blue-300">
                        Your CAs go into a first space named <span className="font-semibold">{data.orgName.trim()}</span>; spaces group CAs for delegated administration.
                    </p>
                </div>
            )}
        </div>
    );
};

export default Organization;
