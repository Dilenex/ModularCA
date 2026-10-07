import { useState } from 'react';

export interface EndpointField {
    name: string;
    type: string;
    required?: boolean;
    description: string;
}

export interface EndpointParam {
    name: string;
    type: string;
    description: string;
}

export interface Endpoint {
    method: 'GET' | 'POST' | 'PUT' | 'DELETE';
    path: string;
    summary: string;
    category: string;
    auth?: string;
    requestBody?: EndpointField[];
    queryParams?: EndpointParam[];
    headers?: EndpointParam[];
    responseDescription?: string;
    notes?: string;
}

const methodColors: Record<string, string> = {
    GET: 'bg-ok-soft text-ok',
    POST: 'bg-info-soft text-accent-ink',
    PUT: 'bg-warn-soft text-warn',
    DELETE: 'bg-crit-soft text-crit',
};

export default function EndpointCard({ endpoint }: { endpoint: Endpoint }) {
    const [expanded, setExpanded] = useState(false);

    const hasDetails =
        (endpoint.requestBody && endpoint.requestBody.length > 0) ||
        (endpoint.queryParams && endpoint.queryParams.length > 0) ||
        (endpoint.headers && endpoint.headers.length > 0) ||
        endpoint.responseDescription ||
        endpoint.notes;

    return (
        <div
            className="bg-raised border border-line rounded-lg overflow-hidden transition-colors hover:border-line-strong"
        >
            <button
                type="button"
                className="w-full text-left px-4 py-3 flex items-center gap-3 cursor-pointer"
                onClick={() => setExpanded((prev) => !prev)}
                aria-expanded={expanded}
            >
                <span
                    className={`inline-flex items-center justify-center px-2 py-0.5 text-xs font-bold rounded-full uppercase tracking-wide min-w-[56px] ${methodColors[endpoint.method] ?? 'bg-sunken text-ink'}`}
                >
                    {endpoint.method}
                </span>

                <code className="data-mono text-ink truncate">
                    {endpoint.path}
                </code>

                <span className="hidden sm:inline text-sm text-ink-muted truncate ml-2">
                    {endpoint.summary}
                </span>

                {endpoint.auth && (
                    <span className="ml-auto mr-2 shrink-0 inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full bg-sunken text-ink-muted">
                        {endpoint.auth}
                    </span>
                )}

                {hasDetails && (
                    <svg
                        className={`w-4 h-4 shrink-0 text-ink-faint transition-transform ${expanded ? 'rotate-180' : ''}`}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                )}
            </button>

            {/* Summary visible on small screens below the header */}
            <p className="sm:hidden px-4 pb-2 text-sm text-ink-muted">
                {endpoint.summary}
            </p>

            {expanded && hasDetails && (
                <div className="px-4 pb-4 space-y-4 border-t border-line pt-4">
                    {/* Request Body */}
                    {endpoint.requestBody && endpoint.requestBody.length > 0 && (
                        <div>
                            <h4 className="text-sm font-semibold text-ink mb-2">
                                Request Body
                            </h4>
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="text-left text-ink-muted border-b border-line">
                                            <th className="pb-2 pr-4 font-medium">Field</th>
                                            <th className="pb-2 pr-4 font-medium">Type</th>
                                            <th className="pb-2 pr-4 font-medium">Required</th>
                                            <th className="pb-2 font-medium">Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {endpoint.requestBody.map((field) => (
                                            <tr
                                                key={field.name}
                                                className="border-b border-line last:border-0"
                                            >
                                                <td className="py-2 pr-4 font-mono text-ink">
                                                    {field.name}
                                                </td>
                                                <td className="py-2 pr-4 text-ink-muted">
                                                    {field.type}
                                                </td>
                                                <td className="py-2 pr-4">
                                                    {field.required ? (
                                                        <span className="text-crit font-medium">Yes</span>
                                                    ) : (
                                                        <span className="text-ink-faint">No</span>
                                                    )}
                                                </td>
                                                <td className="py-2 text-ink-muted">
                                                    {field.description}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Query Parameters */}
                    {endpoint.queryParams && endpoint.queryParams.length > 0 && (
                        <div>
                            <h4 className="text-sm font-semibold text-ink mb-2">
                                Query Parameters
                            </h4>
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="text-left text-ink-muted border-b border-line">
                                            <th className="pb-2 pr-4 font-medium">Parameter</th>
                                            <th className="pb-2 pr-4 font-medium">Type</th>
                                            <th className="pb-2 font-medium">Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {endpoint.queryParams.map((param) => (
                                            <tr
                                                key={param.name}
                                                className="border-b border-line last:border-0"
                                            >
                                                <td className="py-2 pr-4 font-mono text-ink">
                                                    {param.name}
                                                </td>
                                                <td className="py-2 pr-4 text-ink-muted">
                                                    {param.type}
                                                </td>
                                                <td className="py-2 text-ink-muted">
                                                    {param.description}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Headers */}
                    {endpoint.headers && endpoint.headers.length > 0 && (
                        <div>
                            <h4 className="text-sm font-semibold text-ink mb-2">
                                Headers
                            </h4>
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="text-left text-ink-muted border-b border-line">
                                            <th className="pb-2 pr-4 font-medium">Header</th>
                                            <th className="pb-2 pr-4 font-medium">Type</th>
                                            <th className="pb-2 font-medium">Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {endpoint.headers.map((header) => (
                                            <tr
                                                key={header.name}
                                                className="border-b border-line last:border-0"
                                            >
                                                <td className="py-2 pr-4 font-mono text-ink">
                                                    {header.name}
                                                </td>
                                                <td className="py-2 pr-4 text-ink-muted">
                                                    {header.type}
                                                </td>
                                                <td className="py-2 text-ink-muted">
                                                    {header.description}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Response Description */}
                    {endpoint.responseDescription && (
                        <div>
                            <h4 className="text-sm font-semibold text-ink mb-1">
                                Response
                            </h4>
                            <p className="text-sm text-ink-muted">
                                {endpoint.responseDescription}
                            </p>
                        </div>
                    )}

                    {/* Notes */}
                    {endpoint.notes && (
                        <div className="p-3 bg-sunken border border-line rounded-md">
                            <h4 className="text-sm font-semibold text-ink mb-1">
                                Notes
                            </h4>
                            <p className="text-sm text-ink-muted">
                                {endpoint.notes}
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
