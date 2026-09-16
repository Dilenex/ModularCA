import React, { useState, useEffect, useCallback } from 'react';
import { apiGet, apiPost } from '../../api/client';
import { DetailField } from '@shared/components/cards/DetailField';
import { validateAgainstProfileClient } from '@shared/validation/profileValidation';
import { looksLikeHostname } from '@shared/hostname';
import { Link } from 'react-router-dom';
import { inputClass, labelClass } from '@shared/components/forms';

// --- Types ---

interface SanEntry { type: string; value: string; }

interface CsrRequestedExtensions { keyUsage: string[]; extendedKeyUsage: string[]; }

interface ParseCsrResponse {
    subject: Record<string, string>;
    sans: SanEntry[];
    keyAlgorithm: string;
    keySize: string;
    signatureAlgorithm: string;
    requestedExtensions: CsrRequestedExtensions;
    valid: boolean;
    validationErrors: string[];
}

interface FieldValidationResult { field: string; status: 'valid' | 'warning' | 'error'; message: string | null; }
interface SanValidationResult { type: string; value: string; status: 'valid' | 'warning' | 'error'; message: string | null; }
interface ValidateResponse { valid: boolean; fieldResults: FieldValidationResult[]; sanResults: SanValidationResult[]; }

interface SubjectDnFieldRule {
    field: string;
    requirement: string;
    fixedValue?: string | null;
    regex?: string | null;
    maxLength?: number | null;
    defaultValue?: string | null;
}

interface SanTypeRule { regex?: string | null; maxCount: number; }
interface SanRulesObj { allowedTypes: string[]; required: boolean; rules: Record<string, SanTypeRule>; }

interface RequestProfile {
    id: string;
    name: string;
    description?: string | null;
    subjectDnRules: SubjectDnFieldRule[];
    sanRules: SanRulesObj;
    /** JSON array STRING as stored on RequestProfileEntity, e.g. '["guid","guid"]' —
     *  not an array. Read it through parseIdList below. */
    allowedCertProfileIds: string | string[];
    defaultCertProfileId?: string | null;
    requireApproval: boolean;
    maxValidityPeriod?: string | null;
    requiredApprovalCount: number;
}

// --- Constants ---

const DN_FIELDS = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
const SAN_TYPES = ['DNS', 'IP', 'Email', 'URI'];

// --- Helpers ---

function parseRules(raw: any): SubjectDnFieldRule[] {
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return []; } }
    return [];
}

function parseSanRules(raw: any): SanRulesObj {
    const defaults: SanRulesObj = { allowedTypes: SAN_TYPES, required: false, rules: {} };
    if (!raw) return defaults;
    if (typeof raw === 'string') { try { return { ...defaults, ...JSON.parse(raw) }; } catch { return defaults; } }
    return { ...defaults, ...raw };
}

// --- Component ---

/**
 * Reads a field that may arrive as a real array or as a JSON array string. Entity columns that
 * store JSON come back as strings; a few endpoints deserialize them first. Returning [] for
 * anything unparseable is safe here — the caller falls back to no explicit profile.
 */
function parseIdList(value: string | string[] | undefined | null): string[] {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (typeof value !== 'string' || !value.trim()) return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
    } catch {
        return [];
    }
}

const RequestCertificate: React.FC = () => {
    // CSR input
    const [tab, setTab] = useState<'paste' | 'upload' | 'generate'>('paste');
    const [csrPem, setCsrPem] = useState('');
    const [fileName, setFileName] = useState('');
    const [keyAlgorithm, setKeyAlgorithm] = useState('RSA');
    const [keySize, setKeySize] = useState('2048');

    // Parsed CSR data
    const [parsedCsr, setParsedCsr] = useState<ParseCsrResponse | null>(null);
    const [parseError, setParseError] = useState<string | null>(null);
    const [parsing, setParsing] = useState(false);

    // Editable fields
    const [subjectFields, setSubjectFields] = useState<Record<string, string>>({});
    const [sanList, setSanList] = useState<SanEntry[]>([]);

    // Request profile
    const [requestProfiles, setRequestProfiles] = useState<RequestProfile[]>([]);
    const [selectedRequestProfile, setSelectedRequestProfile] = useState('');
    const [validationResult, setValidationResult] = useState<ValidateResponse | null>(null);
    const [validating, setValidating] = useState(false);

    // Signing profiles (for auto-selection)
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);

    // Submit state
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<{ message: string; requiresApproval: boolean; hasPrivateKey?: boolean } | null>(null);

    // --- Initial data load ---
    useEffect(() => {
        apiGet<any>('/api/v1/user/request-profiles')
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setRequestProfiles(items.map((p: any) => ({
                    ...p,
                    subjectDnRules: parseRules(p.subjectDnRules),
                    sanRules: parseSanRules(p.sanRules),
                })));
            })
            .catch(() => {});

        apiGet<any>('/api/v1/user/signing-profiles')
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setSigningProfiles(items);
            })
            .catch(() => {});
    }, []);

    // --- CSR parsing ---
    const parseCsr = useCallback(async (pem: string) => {
        if (!pem.trim()) {
            setParsedCsr(null); setParseError(null); setSubjectFields({}); setSanList([]); setValidationResult(null);
            return;
        }
        setParsing(true);
        setParseError(null);
        try {
            const result = await apiPost<ParseCsrResponse>('/api/v1/user/requests/parse-csr', { pem });
            setParsedCsr(result);
            const fields: Record<string, string> = {};
            for (const f of DN_FIELDS) fields[f] = result.subject[f] || '';
            for (const [k, v] of Object.entries(result.subject)) { if (!DN_FIELDS.includes(k)) fields[k] = v; }
            setSubjectFields(fields);
            setSanList(result.sans.length > 0 ? result.sans.map(s => ({ ...s })) : []);
        } catch (err: any) {
            setParsedCsr(null); setSubjectFields({}); setSanList([]);
            setParseError(err.message || 'Failed to parse CSR');
        } finally { setParsing(false); }
    }, []);

    // Auto-parse on CSR change (debounced)
    useEffect(() => {
        const trimmed = csrPem.trim();
        if (!trimmed) { setParsedCsr(null); setParseError(null); return; }
        if (!trimmed.includes('-----BEGIN') && trimmed.length < 50) return;
        const timer = setTimeout(() => parseCsr(trimmed), 500);
        return () => clearTimeout(timer);
    }, [csrPem, parseCsr]);

    // --- Profile validation ---
    // Two-tier strategy: instant client-side checks per keystroke (no network) + a single
    // server-side confirmation per field-blur (canonical answer). The server stays the source
    // of truth for submission gating; the client mirror is for UX responsiveness only. This
    // replaces the prior 300ms-debounced server hammer that fired ~3 calls/second of typing.
    const hasFieldData = parsedCsr || tab === 'generate';
    // True when subject/sans changed since the last server confirmation; cleared on blur after
    // the server call fires so a tab-through that doesn't actually edit anything stays free.
    const [pendingServerConfirm, setPendingServerConfirm] = useState(false);

    const confirmAgainstServer = useCallback(async (profileId: string) => {
        if (!profileId || !hasFieldData) return;
        setValidating(true);
        try {
            const result = await apiPost<ValidateResponse>('/api/v1/user/requests/validate-against-profile', {
                requestProfileId: profileId,
                subject: subjectFields,
                sans: sanList.filter(s => s.value.trim()),
            });
            setValidationResult(result);
            setPendingServerConfirm(false);
        } catch {
            // Leave the most recent client-side result in place — the server may be transiently
            // unavailable. Submit-time validation will catch any genuine mismatch.
        }
        finally { setValidating(false); }
    }, [hasFieldData, subjectFields, sanList]);

    // Per-keystroke client-side validation. Pure synchronous JS, no network.
    useEffect(() => {
        if (!selectedRequestProfile || !hasFieldData) {
            setValidationResult(null);
            return;
        }
        const profile = requestProfiles.find(p => p.id === selectedRequestProfile);
        if (!profile) return;
        const result = validateAgainstProfileClient(
            subjectFields,
            sanList.filter(s => s.value.trim()),
            profile.subjectDnRules,
            profile.sanRules,
        );
        setValidationResult(result);
        setPendingServerConfirm(true); // mark for next blur to confirm against server
    }, [subjectFields, sanList, selectedRequestProfile, parsedCsr, requestProfiles, hasFieldData]);

    // First server confirmation when a profile is selected — gives the operator a canonical
    // "yes the profile rules really say this" answer right away. Client-side runs above already.
    useEffect(() => {
        if (selectedRequestProfile && hasFieldData) {
            confirmAgainstServer(selectedRequestProfile);
        }
    }, [selectedRequestProfile]); // eslint-disable-line react-hooks/exhaustive-deps

    // Field-blur handler: if anything changed since the last server confirm, fire one server
    // call. Tab-through-without-edits stays free. Use on every editable input/select.
    const handleFieldBlur = useCallback(() => {
        if (pendingServerConfirm && selectedRequestProfile && hasFieldData) {
            confirmAgainstServer(selectedRequestProfile);
        }
    }, [pendingServerConfirm, selectedRequestProfile, hasFieldData, confirmAgainstServer]);

    // --- File upload ---
    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setFileName(file.name);
        const reader = new FileReader();
        reader.onload = (ev) => setCsrPem(ev.target?.result as string || '');
        reader.readAsText(file);
    };

    // --- SAN helpers ---
    const addSan = () => setSanList([...sanList, { type: 'DNS', value: '' }]);
    const removeSan = (idx: number) => setSanList(sanList.filter((_, i) => i !== idx));
    const updateSan = (idx: number, field: 'type' | 'value', val: string) => {
        const updated = [...sanList];
        updated[idx] = { ...updated[idx], [field]: val };
        setSanList(updated);
    };

    const updateSubjectField = (field: string, value: string) => setSubjectFields(prev => ({ ...prev, [field]: value }));

    const getFieldValidation = (field: string) => validationResult?.fieldResults.find(r => r.field === field);
    const getSanValidation = (idx: number) => validationResult?.sanResults[idx];

    const selectedProfileObj = requestProfiles.find(p => p.id === selectedRequestProfile);
    const getRuleForField = (field: string) => selectedProfileObj?.subjectDnRules?.find(r => r.field === field);


    const cnValue = (subjectFields['CN'] ?? '').trim();

    const cnAlreadyASan = sanList.some(
        s => s.type === 'DNS' && s.value.trim().toLowerCase() === cnValue.toLowerCase());

    // Never offer an action the profile forbids — that would be a one-click route to a
    // validation failure.
    const profileAllowsDnsSan = (() => {
        const allowed = selectedProfileObj?.sanRules?.allowedTypes;
        if (!allowed) return true;
        return allowed.some(t => t.toUpperCase() === 'DNS');
    })();

    const canAddCnAsSan = looksLikeHostname(cnValue) && !cnAlreadyASan && profileAllowsDnsSan;

    const addCnAsSan = () => {
        if (!canAddCnAsSan) return;
        // Reuse a blank DNS row rather than leaving an empty one behind to fail validation.
        const blankIdx = sanList.findIndex(s => s.type === 'DNS' && !s.value.trim());
        if (blankIdx >= 0) updateSan(blankIdx, 'value', cnValue);
        else setSanList([...sanList, { type: 'DNS', value: cnValue }]);
    };

    // --- Submit ---
    const hasValidationErrors = validationResult && !validationResult.valid;

    const handleSubmit = async () => {
        if (!selectedRequestProfile) { setError('Please select a request profile.'); return; }
        if (tab !== 'generate' && !csrPem.trim()) { setError('Please provide a CSR.'); return; }

        setLoading(true); setError(null); setSuccess(null);

        try {
            const subjectOverrides: Record<string, string> = {};
            for (const [k, v] of Object.entries(subjectFields)) { if (v.trim()) subjectOverrides[k] = v.trim(); }

            const sanOverrides = sanList.filter(s => s.value.trim()).map(s => ({ type: s.type, value: s.value.trim() }));

            // allowedCertProfileIds arrives as a JSON array STRING, because
            // RequestProfileEntity.AllowedCertProfileIds is a string column defaulting to "[]".
            // Indexing it as an array took the first CHARACTER: '[' was sent as certProfileId
            // and rejected as a malformed Guid, so any request profile without an explicit
            // default cert profile simply could not be used.
            const allowedIds = parseIdList(selectedProfileObj?.allowedCertProfileIds);
            const certProfileId = selectedProfileObj?.defaultCertProfileId || allowedIds[0];
            const signingProfileId = signingProfiles.find(s => s.isDefault)?.id || signingProfiles[0]?.id;

            if (tab === 'generate') {
                if (Object.keys(subjectOverrides).length === 0) {
                    setError('Please fill in at least one subject field (e.g., CN).');
                    setLoading(false);
                    return;
                }

                await apiPost<any>('/api/v1/user/requests/request-with-key', {
                    subject: subjectOverrides,
                    sans: sanOverrides,
                    keyAlgorithm,
                    keySize: (keyAlgorithm === 'Ed25519' || keyAlgorithm === 'Ed448' || keyAlgorithm.startsWith('ML-DSA') || keyAlgorithm.startsWith('SLH-DSA')) ? keyAlgorithm : keySize,
                    certProfileId: certProfileId,
                    signingProfileId,
                });

                setSuccess({
                    message: 'Your certificate request has been submitted with a server-generated key pair. Once approved and issued, you can download the PFX from your certificates page.',
                    requiresApproval: true,
                    hasPrivateKey: true,
                });
            } else {
                await apiPost<any>('/api/v1/user/requests/upload', {
                    pem: csrPem.trim(),
                    certificateProfileId: certProfileId,
                    signingProfileId,
                    subjectOverrides: Object.keys(subjectOverrides).length > 0 ? subjectOverrides : undefined,
                    sanOverrides: sanOverrides.length > 0 ? sanOverrides : undefined,
                });

                setSuccess({
                    message: selectedProfileObj?.requireApproval
                        ? 'Your certificate request has been submitted and will be reviewed by an administrator.'
                        : 'Your certificate request has been submitted and is being processed.',
                    requiresApproval: !!selectedProfileObj?.requireApproval,
                });
            }

            setCsrPem(''); setFileName(''); setParsedCsr(null); setSubjectFields({}); setSanList([]); setValidationResult(null);
        } catch (err: any) {
            setError(err.message || 'Certificate request failed');
        } finally { setLoading(false); }
    };

    // --- Styles ---

    const statusIcon = (status?: string) => {
        if (!status) return null;
        if (status === 'valid') return <span className="text-green-800 dark:text-green-400 text-sm ml-2" title="Valid">&#10003;</span>;
        if (status === 'warning') return <span className="text-yellow-800 dark:text-yellow-400 text-sm ml-2" title="Warning">&#9888;</span>;
        if (status === 'error') return <span className="text-red-800 dark:text-red-400 text-sm ml-2" title="Error">&#10007;</span>;
        return null;
    };

    const statusBorder = (status?: string) => {
        if (status === 'valid') return 'border-green-300 dark:border-green-600';
        if (status === 'warning') return 'border-yellow-300 dark:border-yellow-600';
        if (status === 'error') return 'border-red-300 dark:border-red-600';
        return 'border-gray-300 dark:border-gray-700';
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Request Certificate</h1>

            {/* Step 1: CSR Input */}
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Step 1: Certificate Signing Request</h3>
                </div>
                <div className="p-4 space-y-4">
                    <div className="flex gap-2">
                        <button onClick={() => setTab('paste')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'paste' ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700' : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'}`}>
                            Paste CSR
                        </button>
                        <button onClick={() => setTab('upload')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'upload' ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700' : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'}`}>
                            Upload CSR File
                        </button>
                        <button onClick={() => setTab('generate')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'generate' ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700' : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'}`}>
                            Generate Key Pair
                        </button>
                    </div>

                    {tab === 'paste' && (
                        <div>
                            <label className={labelClass}>PEM-encoded CSR</label>
                            <textarea value={csrPem} onChange={(e) => setCsrPem(e.target.value)}
                                placeholder={"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}
                                rows={8} className={`${inputClass} font-mono resize-y`} />
                        </div>
                    )}

                    {tab === 'upload' && (
                        <div>
                            <label className={labelClass}>CSR File (.pem, .csr)</label>
                            <input type="file" accept=".pem,.csr,.req,.txt" onChange={handleFileUpload}
                                className="block w-full text-sm text-gray-600 dark:text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border file:border-gray-400 dark:file:border-gray-600 file:text-sm file:bg-gray-200 dark:file:bg-gray-700 file:text-gray-700 dark:file:text-gray-300 hover:file:bg-gray-600" />
                            {fileName && <p className="mt-2 text-xs text-gray-600 dark:text-gray-400">Loaded: {fileName}</p>}
                            {csrPem && tab === 'upload' && (
                                <pre className="mt-2 p-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-xs text-gray-600 dark:text-gray-400 font-mono max-h-40 overflow-auto">
                                    {csrPem.substring(0, 500)}{csrPem.length > 500 ? '...' : ''}
                                </pre>
                            )}
                        </div>
                    )}

                    {tab === 'generate' && (
                        <div className="space-y-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <label className={labelClass}>Key Algorithm</label>
                                    <select value={keyAlgorithm} onChange={(e) => {
                                        const alg = e.target.value;
                                        setKeyAlgorithm(alg);
                                        if (alg === 'RSA') setKeySize('2048');
                                        else if (alg === 'ECDSA') setKeySize('P-256');
                                        else setKeySize('');
                                    }} className={inputClass}>
                                        <option value="RSA">RSA</option>
                                        <option value="ECDSA">ECDSA</option>
                                        <option value="Ed25519">Ed25519</option>
                                        <option value="Ed448">Ed448</option>
                                        <option value="ML-DSA-44">ML-DSA-44</option>
                                        <option value="ML-DSA-65">ML-DSA-65</option>
                                        <option value="ML-DSA-87">ML-DSA-87</option>
                                        <option value="SLH-DSA-SHA2-128F">SLH-DSA-SHA2-128F</option>
                                    </select>
                                </div>
                                {keyAlgorithm !== 'Ed25519' && keyAlgorithm !== 'Ed448' && !keyAlgorithm.startsWith('ML-DSA') && !keyAlgorithm.startsWith('SLH-DSA') && (
                                    <div>
                                        <label className={labelClass}>Key Size</label>
                                        <select value={keySize} onChange={(e) => setKeySize(e.target.value)} className={inputClass}>
                                            {keyAlgorithm === 'RSA' && <><option value="2048">2048</option><option value="3072">3072</option><option value="4096">4096</option><option value="7680">7680 (high compute)</option><option value="8192">8192 (high compute)</option></>}
                                            {keyAlgorithm === 'ECDSA' && <><option value="P-256">P-256</option><option value="P-384">P-384</option><option value="P-521">P-521</option></>}
                                        </select>
                                        {keyAlgorithm === 'RSA' && (keySize === '7680' || keySize === '8192') && (
                                            <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                                                ⚠ High-compute RSA — key generation may take 30+ seconds.
                                            </p>
                                        )}
                                    </div>
                                )}
                            </div>
                            <p className="text-xs text-gray-600">
                                The server will generate a key pair and build a CSR automatically.
                                The private key is stored encrypted and can be exported as PFX after the certificate is issued.
                            </p>
                        </div>
                    )}

                    {parsing && <p className="text-xs text-gray-600 dark:text-gray-400">Parsing CSR...</p>}
                    {parseError && <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded p-3"><p className="text-sm text-red-800 dark:text-red-300">{parseError}</p></div>}

                    {parsedCsr && (
                        <div className="flex flex-wrap gap-2">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">
                                {parsedCsr.keyAlgorithm} {parsedCsr.keySize && `(${parsedCsr.keySize})`}
                            </span>
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-900/40 text-purple-300 border border-purple-800">
                                {parsedCsr.signatureAlgorithm}
                            </span>
                            {parsedCsr.valid
                                ? <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-800">Signature Valid</span>
                                : <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-50 dark:bg-red-900/40 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800">Signature Invalid</span>
                            }
                        </div>
                    )}
                </div>
            </div>

            {/* Step 2: Request Profile */}
            {(parsedCsr || tab === 'generate') && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Step 2: Request Profile</h3>
                        {validating && <span className="text-xs text-gray-600 dark:text-gray-400">Validating...</span>}
                        {validationResult && !validating && (
                            validationResult.valid
                                ? <span className="text-xs text-green-800 dark:text-green-400">All checks passed</span>
                                : <span className="text-xs text-red-800 dark:text-red-400">Validation errors found</span>
                        )}
                    </div>
                    <div className="p-4">
                        <label className={labelClass}>Request Profile</label>
                        <select value={selectedRequestProfile} onChange={(e) => setSelectedRequestProfile(e.target.value)} className={inputClass}>
                            <option value="">-- Select a Request Profile --</option>
                            {requestProfiles.map((p) => (
                                <option key={p.id} value={p.id}>{p.name}{p.description ? ` \u2014 ${p.description}` : ''}</option>
                            ))}
                        </select>
                        {selectedProfileObj && (
                            <div className="mt-2 flex flex-wrap gap-2">
                                {selectedProfileObj.requireApproval && (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-50 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-300 border border-yellow-300 dark:border-yellow-800">Requires Approval</span>
                                )}
                                {selectedProfileObj.maxValidityPeriod && (
                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-400 dark:border-gray-600">Max validity: {selectedProfileObj.maxValidityPeriod}</span>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Step 3: Certificate Fields */}
            {(parsedCsr || tab === 'generate') && selectedRequestProfile && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Step 3: Certificate Fields</h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">Pre-filled from CSR. Edit as needed.</p>
                    </div>
                    <div className="p-4 space-y-4">
                        <div>
                            <h4 className="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-3 uppercase tracking-wide">Subject DN</h4>
                            <div className="space-y-3">
                                {DN_FIELDS.map((field) => {
                                    const validation = getFieldValidation(field);
                                    const rule = getRuleForField(field);
                                    const borderClass = validation ? statusBorder(validation.status) : 'border-gray-300 dark:border-gray-700';
                                    return (
                                        <div key={field} className="flex items-start gap-3">
                                            <label className="w-12 pt-2 text-xs font-mono font-semibold text-gray-600 dark:text-gray-400 text-right flex-shrink-0">{field}:</label>
                                            <div className="flex-1">
                                                <div className="flex items-center">
                                                    <input type="text" value={subjectFields[field] || ''}
                                                        onChange={(e) => updateSubjectField(field, e.target.value)}
                                                        onBlur={handleFieldBlur}
                                                        className={`flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-900 border ${borderClass} rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500`}
                                                        placeholder={rule?.defaultValue || ''} disabled={!!rule?.fixedValue} />
                                                    {statusIcon(validation?.status)}
                                                </div>
                                                {validation?.message && (
                                                    <p className={`text-xs mt-1 ${validation.status === 'error' ? 'text-red-800 dark:text-red-400' : validation.status === 'warning' ? 'text-yellow-800 dark:text-yellow-400' : 'text-green-800 dark:text-green-400'}`}>
                                                        {validation.message}
                                                    </p>
                                                )}
                                                {rule && !validation?.message && (
                                                    <p className="text-xs mt-1 text-gray-600">
                                                        {rule.requirement}
                                                        {rule.regex ? ` | Pattern: ${rule.regex}` : ''}
                                                        {rule.maxLength ? ` | Max: ${rule.maxLength}` : ''}
                                                        {rule.fixedValue ? ` | Fixed: ${rule.fixedValue}` : ''}
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        <div>
                            <h4 className="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-3 uppercase tracking-wide">Subject Alternative Names</h4>
                            <div className="space-y-2">
                                {sanList.map((san, idx) => {
                                    const sanValidation = getSanValidation(idx);
                                    const borderClass = sanValidation ? statusBorder(sanValidation.status) : 'border-gray-300 dark:border-gray-700';
                                    return (
                                        <div key={idx}>
                                            <div className="flex items-center gap-2">
                                                <select value={san.type}
                                                    onChange={(e) => updateSan(idx, 'type', e.target.value)}
                                                    onBlur={handleFieldBlur}
                                                    className="px-2 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 w-24 flex-shrink-0">
                                                    {SAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                                                </select>
                                                <input type="text" value={san.value}
                                                    onChange={(e) => updateSan(idx, 'value', e.target.value)}
                                                    onBlur={handleFieldBlur}
                                                    className={`flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-900 border ${borderClass} rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500`}
                                                    placeholder={`${san.type} value`} />
                                                {statusIcon(sanValidation?.status)}
                                                <button onClick={() => removeSan(idx)} className="px-2 py-2 text-sm text-red-800 dark:text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded transition-colors" title="Remove SAN">&#10005;</button>
                                            </div>
                                            {sanValidation?.message && (
                                                <p className={`text-xs mt-1 ml-28 ${sanValidation.status === 'error' ? 'text-red-800 dark:text-red-400' : sanValidation.status === 'warning' ? 'text-yellow-800 dark:text-yellow-400' : 'text-green-800 dark:text-green-400'}`}>
                                                    {sanValidation.message}
                                                </p>
                                            )}
                                        </div>
                                    );
                                })}
                                <div className="flex flex-wrap items-center gap-2">
                                    <button onClick={addSan} className="px-3 py-1.5 text-xs text-blue-800 dark:text-blue-400 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900/30 transition-colors">+ Add SAN</button>
                                    {canAddCnAsSan && (
                                        <button onClick={addCnAsSan}
                                            title={`Add ${cnValue} as a DNS Subject Alternative Name`}
                                            className="px-3 py-1.5 text-xs text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900/30 transition-colors">
                                            + Use CN as DNS SAN
                                            <span className="ml-1.5 font-mono opacity-80">{cnValue}</span>
                                        </button>
                                    )}
                                </div>
                            </div>
                            {canAddCnAsSan && (
                                <p className="text-xs text-yellow-800 dark:text-yellow-400 mt-2">
                                    <span className="font-semibold">{cnValue}</span> is not listed as a DNS SAN.
                                    Clients ignore the Common Name for hostname verification, so this
                                    certificate would not validate for that name.
                                </p>
                            )}
                            {selectedProfileObj?.sanRules && (
                                <p className="text-xs text-gray-600 mt-2">
                                    Allowed types: {selectedProfileObj.sanRules.allowedTypes?.join(', ') || 'Any'}
                                    {selectedProfileObj.sanRules.required ? ' | At least one SAN required' : ''}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Step 4: Submit */}
            <div className="flex items-center gap-4">
                <button onClick={handleSubmit}
                    disabled={loading || !selectedRequestProfile || (tab !== 'generate' && !csrPem.trim()) || !!hasValidationErrors}
                    className="px-6 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                    {loading ? 'Submitting...' : (tab === 'generate' ? 'Generate Key & Submit Request' : 'Submit Request')}
                </button>
                {hasValidationErrors && <span className="text-xs text-red-800 dark:text-red-400">Fix validation errors before submitting.</span>}
            </div>

            {error && <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-lg p-4"><p className="text-sm text-red-800 dark:text-red-300">{error}</p></div>}

            {success && (
                <div className={`${success.requiresApproval ? 'bg-yellow-50 dark:bg-yellow-900/30 border-yellow-300 dark:border-yellow-700' : 'bg-green-50 dark:bg-green-900/30 border-green-300 dark:border-green-700'} border rounded-lg p-4 space-y-3`}>
                    <p className={`text-sm font-semibold ${success.requiresApproval ? 'text-yellow-800 dark:text-yellow-300' : 'text-green-800 dark:text-green-300'}`}>{success.message}</p>
                    {success.requiresApproval && <DetailField label="Approvals Required" value={String(selectedProfileObj?.requiredApprovalCount || 1)} />}
                    <div className="flex gap-3 pt-2">
                        <Link to="/requests" className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">View My Requests</Link>
                        <button onClick={() => { setSuccess(null); setSelectedRequestProfile(''); }}
                            className="px-4 py-2 text-sm text-blue-800 dark:text-blue-400 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900/30 transition-colors">Submit Another</button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RequestCertificate;
