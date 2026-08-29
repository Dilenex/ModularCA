import React, { useState, useEffect, useCallback } from 'react';
import { apiGet, apiPost } from '../api/client';
import { DetailField } from '@shared/components/cards/DetailField';
import { validateAgainstProfileClient } from '@shared/validation/profileValidation';
import { looksLikeHostname } from '@shared/hostname';
import { inputClass, labelClass } from '@shared/components/forms';

// --- Types ---

interface SanEntry {
    type: string;
    value: string;
}

interface CsrRequestedExtensions {
    keyUsage: string[];
    extendedKeyUsage: string[];
}

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

interface FieldValidationResult {
    field: string;
    status: 'valid' | 'warning' | 'error';
    message: string | null;
}

interface SanValidationResult {
    type: string;
    value: string;
    status: 'valid' | 'warning' | 'error';
    message: string | null;
}

interface ValidateResponse {
    valid: boolean;
    fieldResults: FieldValidationResult[];
    sanResults: SanValidationResult[];
}

interface RequestProfile {
    id: string;
    name: string;
    description?: string;
    subjectDnRules: SubjectDnFieldRule[];
    sanRules: SanRulesObj;
}

interface SubjectDnFieldRule {
    field: string;
    requirement: string;
    fixedValue?: string | null;
    regex?: string | null;
    maxLength?: number | null;
    defaultValue?: string | null;
}

interface SanTypeRule {
    regex?: string | null;
    maxCount: number;
}

interface SanRulesObj {
    allowedTypes: string[];
    required: boolean;
    rules: Record<string, SanTypeRule>;
}

// --- Constants ---

const DN_FIELDS = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
// UPN is a Microsoft otherName (1.3.6.1.4.1.311.20.2.3) and is how Windows maps a smart-card
// logon certificate to an Active Directory account. Unlike the others it names a principal rather
// than a network endpoint, so a request profile has to list it in allowedTypes before it can be
// used — see RequestProfiles.
const SAN_TYPES = ['DNS', 'IP', 'Email', 'URI', 'UPN'];

// --- Component ---

const IssueCertificate: React.FC = () => {
    // CSR input
    const [tab, setTab] = useState<'paste' | 'upload' | 'generate'>('paste');
    const [csrPem, setCsrPem] = useState('');
    const [fileName, setFileName] = useState('');

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

    // Issuance options
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [selectedSigningProfile, setSelectedSigningProfile] = useState('');
    const [selectedCertProfile, setSelectedCertProfile] = useState('');
    const [notBefore, setNotBefore] = useState('');
    const [notAfter, setNotAfter] = useState('');
    // Generate key pair state
    const [keyAlgorithm, setKeyAlgorithm] = useState('RSA');
    const [keySize, setKeySize] = useState('2048');

    // Submit state
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<{ serial: string; hasPrivateKey?: boolean } | null>(null);

    // --- Initial data load ---
    useEffect(() => {
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setSigningProfiles(items);
                if (items.length > 0) setSelectedSigningProfile(items[0].id || items[0].name || '');
            })
            .catch(() => {});

        apiGet<any>('/api/v1/admin/cert-profiles?isCaProfile=false')
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setCertProfiles(items);
                if (items.length > 0) setSelectedCertProfile(items[0].id || items[0].name || '');
            })
            .catch(() => {});

        apiGet<any>('/api/v1/admin/request-profiles')
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setRequestProfiles(items);
            })
            .catch(() => {});

        // <input type="datetime-local"> reads its value as LOCAL time, so it must be seeded
        // with local wall-clock components. toISOString() returns UTC: seeding from it put a
        // UTC clock reading into a local-time field, so the form opened pre-filled with a
        // notBefore one UTC-offset in the future, and the certificate was issued starting
        // then — invalid to every relying party until that time arrived.
        const toLocalInputValue = (d: Date) => {
            const pad = (v: number) => String(v).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
                + `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        };
        const now = new Date();
        const oneYear = new Date(now);
        oneYear.setFullYear(oneYear.getFullYear() + 1);
        setNotBefore(toLocalInputValue(now));
        setNotAfter(toLocalInputValue(oneYear));
    }, []);

    // --- CSR parsing ---
    const parseCsr = useCallback(async (pem: string) => {
        if (!pem.trim()) {
            setParsedCsr(null);
            setParseError(null);
            setSubjectFields({});
            setSanList([]);
            setValidationResult(null);
            return;
        }
        setParsing(true);
        setParseError(null);
        try {
            const result = await apiPost<ParseCsrResponse>('/api/v1/admin/requests/parse-csr', { pem });
            setParsedCsr(result);
            // Pre-fill editable fields from parsed CSR
            const fields: Record<string, string> = {};
            for (const f of DN_FIELDS) {
                fields[f] = result.subject[f] || '';
            }
            // Also include any extra fields from the CSR
            for (const [k, v] of Object.entries(result.subject)) {
                if (!DN_FIELDS.includes(k)) fields[k] = v;
            }
            setSubjectFields(fields);
            setSanList(result.sans.length > 0 ? result.sans.map(s => ({ ...s })) : []);
            setParseError(null);
        } catch (err: any) {
            setParsedCsr(null);
            setSubjectFields({});
            setSanList([]);
            setParseError(err.message || 'Failed to parse CSR');
        } finally {
            setParsing(false);
        }
    }, []);

    // Auto-parse on CSR change (debounced)
    useEffect(() => {
        const trimmed = csrPem.trim();
        if (!trimmed) {
            setParsedCsr(null);
            setParseError(null);
            return;
        }
        // Only parse if it looks like a CSR
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
            const result = await apiPost<ValidateResponse>('/api/v1/admin/requests/validate-against-profile', {
                requestProfileId: profileId,
                subject: subjectFields,
                sans: sanList.filter(s => s.value.trim()),
            });
            setValidationResult(result);
            setPendingServerConfirm(false);
        } catch {
            // Leave the most recent client-side result in place — the server may be transiently
            // unavailable. Submit-time validation will catch any genuine mismatch.
        } finally {
            setValidating(false);
        }
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
    // call. Tab-through-without-edits stays free.
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
        reader.onload = (ev) => {
            setCsrPem(ev.target?.result as string || '');
        };
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

    // --- Subject field update ---
    const updateSubjectField = (field: string, value: string) => {
        setSubjectFields(prev => ({ ...prev, [field]: value }));
    };

    // --- Get validation status for a field ---
    const getFieldValidation = (field: string): FieldValidationResult | undefined => {
        return validationResult?.fieldResults.find(r => r.field === field);
    };

    const getSanValidation = (idx: number): SanValidationResult | undefined => {
        if (!validationResult) return undefined;
        // Match by index in the sanResults list
        return validationResult.sanResults[idx];
    };

    // --- Submit ---
    const hasValidationErrors = validationResult && !validationResult.valid;

    const handleSubmit = async () => {
        if (!selectedRequestProfile) { setError('Please select a request profile.'); return; }
        if (!selectedSigningProfile) { setError('Please select a signing profile.'); return; }
        if (!selectedCertProfile) { setError('Please select a certificate profile.'); return; }

        setLoading(true);
        setError(null);
        setSuccess(null);

        try {
            if (tab === 'generate') {
                // Server-side key generation flow — creates request, does NOT issue immediately
                const subject: Record<string, string> = {};
                for (const [k, v] of Object.entries(subjectFields)) {
                    if (v.trim()) subject[k] = v.trim();
                }
                if (Object.keys(subject).length === 0) {
                    setError('Please fill in at least one subject field (e.g., CN).');
                    setLoading(false);
                    return;
                }

                const sans = sanList
                    .filter(s => s.value.trim())
                    .map(s => ({ type: s.type, value: s.value.trim() }));

                await apiPost<any>('/api/v1/admin/certificates/issue-with-key', {
                    subject,
                    sans,
                    keyAlgorithm,
                    keySize: (keyAlgorithm === 'Ed25519' || keyAlgorithm === 'Ed448' || keyAlgorithm.startsWith('ML-DSA') || keyAlgorithm.startsWith('SLH-DSA')) ? keyAlgorithm : keySize,
                    certProfileId: selectedCertProfile,
                    signingProfileId: selectedSigningProfile,
                    notBefore: notBefore ? new Date(notBefore).toISOString() : undefined,
                    notAfter: notAfter ? new Date(notAfter).toISOString() : undefined,
                });

                setSuccess({
                    serial: 'Request submitted with server-generated key pair. Approve and issue from the Requests page.',
                    hasPrivateKey: true,
                });
                setSubjectFields({});
                setSanList([]);
                setSelectedRequestProfile('');
                setValidationResult(null);
            } else {
                // Standard CSR upload flow
                const pem = csrPem.trim();
                if (!pem) { setError('Please provide a CSR.'); setLoading(false); return; }

                const subjectOverrides: Record<string, string> = {};
                for (const [k, v] of Object.entries(subjectFields)) {
                    if (v.trim()) subjectOverrides[k] = v.trim();
                }

                const sanOverrides = sanList
                    .filter(s => s.value.trim())
                    .map(s => ({ type: s.type, value: s.value.trim() }));

                await apiPost<any>('/api/v1/admin/requests/upload', {
                    pem,
                    signingProfileId: selectedSigningProfile,
                    certificateProfileId: selectedCertProfile,
                    subjectOverrides: Object.keys(subjectOverrides).length > 0 ? subjectOverrides : undefined,
                    sanOverrides: sanOverrides.length > 0 ? sanOverrides : undefined,
                    notBefore: notBefore ? new Date(notBefore).toISOString() : undefined,
                    notAfter: notAfter ? new Date(notAfter).toISOString() : undefined,
                });

                setSuccess({ serial: 'CSR uploaded successfully' });
                setCsrPem('');
                setFileName('');
                setParsedCsr(null);
                setSubjectFields({});
                setSanList([]);
                setSelectedRequestProfile('');
                setValidationResult(null);
            }
        } catch (err: any) {
            setError(err.message || 'Certificate issuance failed');
        } finally {
            setLoading(false);
        }
    };

    // --- Styles ---

    const statusIcon = (status?: string) => {
        if (!status) return null;
        switch (status) {
            case 'valid': return <span className="text-green-800 dark:text-green-400 text-sm ml-2" title="Valid">&#10003;</span>;
            case 'warning': return <span className="text-yellow-800 dark:text-yellow-400 text-sm ml-2" title="Warning">&#9888;</span>;
            case 'error': return <span className="text-red-800 dark:text-red-400 text-sm ml-2" title="Error">&#10007;</span>;
            default: return null;
        }
    };

    const statusBorder = (status?: string) => {
        switch (status) {
            case 'valid': return 'border-green-300 dark:border-green-600';
            case 'warning': return 'border-yellow-300 dark:border-yellow-600';
            case 'error': return 'border-red-300 dark:border-red-600';
            default: return 'border-gray-300 dark:border-gray-700';
        }
    };

    // Find the selected profile for tooltip info
    const selectedProfileObj = requestProfiles.find(p => p.id === selectedRequestProfile);

    const cnValue = (subjectFields['CN'] ?? '').trim();

    // Offer the action only when it would actually change something: the CN is hostname-shaped
    // and is not already present as a DNS SAN (case-insensitive, since DNS is).
    const cnAlreadyASan = sanList.some(
        s => s.type === 'DNS' && s.value.trim().toLowerCase() === cnValue.toLowerCase());
    // Respect the request profile. Offering to add a DNS SAN to a profile that forbids SANs —
    // or permits only Email/IP — would hand the operator a one-click way to fail validation.
    const profileAllowsDnsSan = (() => {
        const allowed = selectedProfileObj?.sanRules?.allowedTypes;
        if (!allowed) return true;                 // no rules configured means no restriction
        return allowed.some(t => t.toUpperCase() === 'DNS');
    })();

    const canAddCnAsSan = looksLikeHostname(cnValue) && !cnAlreadyASan && profileAllowsDnsSan;

    const addCnAsSan = () => {
        if (!canAddCnAsSan) return;
        // Reuse a blank DNS row if the operator already added one, rather than leaving an empty
        // row behind that will fail validation.
        const blankIdx = sanList.findIndex(s => s.type === 'DNS' && !s.value.trim());
        if (blankIdx >= 0) {
            updateSan(blankIdx, 'value', cnValue);
        } else {
            setSanList([...sanList, { type: 'DNS', value: cnValue }]);
        }
    };

    const getRuleForField = (field: string): SubjectDnFieldRule | undefined => {
        return selectedProfileObj?.subjectDnRules?.find(r => r.field === field);
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Request Certificate</h1>

            {/* Step 1: CSR Input Card */}
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Step 1: Certificate Signing Request</h3>
                </div>
                <div className="p-4 space-y-4">
                    <div className="flex gap-2">
                        <button
                            onClick={() => setTab('paste')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${
                                tab === 'paste'
                                    ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700'
                                    : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'
                            }`}
                        >
                            Paste CSR
                        </button>
                        <button
                            onClick={() => setTab('upload')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${
                                tab === 'upload'
                                    ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700'
                                    : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'
                            }`}
                        >
                            Upload CSR File
                        </button>
                        <button
                            onClick={() => setTab('generate')}
                            className={`px-4 py-2 text-sm rounded transition-colors ${
                                tab === 'generate'
                                    ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700'
                                    : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-400 dark:border-gray-600 hover:bg-gray-300 dark:hover:bg-gray-600'
                            }`}
                        >
                            Generate Key Pair
                        </button>
                    </div>

                    {tab === 'paste' && (
                        <div>
                            <label className={labelClass}>PEM-encoded CSR</label>
                            <textarea
                                value={csrPem}
                                onChange={(e) => setCsrPem(e.target.value)}
                                placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
                                rows={8}
                                className={`${inputClass} font-mono resize-y`}
                            />
                        </div>
                    )}

                    {tab === 'upload' && (
                        <div>
                            <label className={labelClass}>CSR File (.pem, .csr)</label>
                            <input
                                type="file"
                                accept=".pem,.csr,.req,.txt"
                                onChange={handleFileUpload}
                                className="block w-full text-sm text-gray-600 dark:text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border file:border-gray-400 dark:border-gray-600 file:text-sm file:bg-gray-200 dark:bg-gray-700 file:text-gray-700 dark:text-gray-300 hover:file:bg-gray-600"
                            />
                            {fileName && (
                                <p className="mt-2 text-xs text-gray-600 dark:text-gray-400">Loaded: {fileName}</p>
                            )}
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
                                    <select
                                        value={keyAlgorithm}
                                        onChange={(e) => {
                                            const alg = e.target.value;
                                            setKeyAlgorithm(alg);
                                            if (alg === 'RSA') setKeySize('2048');
                                            else if (alg === 'ECDSA') setKeySize('P-256');
                                            else setKeySize('');
                                        }}
                                        className={inputClass}
                                    >
                                        {(() => {
                                            const allAlgorithms = ['RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128F'];
                                            const selectedProfile = certProfiles.find((p: any) => p.id === selectedCertProfile);
                                            let allowed = allAlgorithms;
                                            if (selectedProfile?.allowedKeyAlgorithms) {
                                                try {
                                                    const parsed = typeof selectedProfile.allowedKeyAlgorithms === 'string'
                                                        ? JSON.parse(selectedProfile.allowedKeyAlgorithms)
                                                        : selectedProfile.allowedKeyAlgorithms;
                                                    if (Array.isArray(parsed) && parsed.length > 0) {
                                                        allowed = allAlgorithms.filter(a =>
                                                            parsed.some((p: string) => p.toUpperCase() === a.toUpperCase())
                                                        );
                                                    }
                                                } catch { /* use all */ }
                                            }
                                            return allowed.map(a => (
                                                <option key={a} value={a}>{a}</option>
                                            ));
                                        })()}
                                    </select>
                                </div>
                                {keyAlgorithm !== 'Ed25519' && keyAlgorithm !== 'Ed448' && !keyAlgorithm.startsWith('ML-DSA') && !keyAlgorithm.startsWith('SLH-DSA') && (
                                    <div>
                                        <label className={labelClass}>Key Size</label>
                                        <select
                                            value={keySize}
                                            onChange={(e) => setKeySize(e.target.value)}
                                            className={inputClass}
                                        >
                                            {keyAlgorithm === 'RSA' && (
                                                <>
                                                    <option value="2048">2048</option>
                                                    <option value="3072">3072</option>
                                                    <option value="4096">4096</option>
                                                    <option value="7680">7680 (high compute)</option>
                                                    <option value="8192">8192 (high compute)</option>
                                                </>
                                            )}
                                            {keyAlgorithm === 'ECDSA' && (
                                                <>
                                                    <option value="P-256">P-256</option>
                                                    <option value="P-384">P-384</option>
                                                    <option value="P-521">P-521</option>
                                                </>
                                            )}
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
                                The private key will be stored encrypted and can be exported as PFX after issuance.
                            </p>
                        </div>
                    )}

                    {/* Parse status */}
                    {parsing && (
                        <p className="text-xs text-gray-600 dark:text-gray-400">Parsing CSR...</p>
                    )}
                    {parseError && (
                        <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded p-3">
                            <p className="text-sm text-red-800 dark:text-red-300">{parseError}</p>
                        </div>
                    )}

                    {/* Key info badges */}
                    {parsedCsr && (
                        <div className="flex flex-wrap gap-2">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">
                                {parsedCsr.keyAlgorithm} {parsedCsr.keySize && `(${parsedCsr.keySize})`}
                            </span>
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-900/40 text-purple-300 border border-purple-800">
                                {parsedCsr.signatureAlgorithm}
                            </span>
                            {parsedCsr.valid ? (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 dark:bg-green-900/40 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-800">
                                    Signature Valid
                                </span>
                            ) : (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-50 dark:bg-red-900/40 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800">
                                    Signature Invalid
                                </span>
                            )}
                            {parsedCsr.requestedExtensions.keyUsage.length > 0 && (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-400 dark:border-gray-600" title={parsedCsr.requestedExtensions.keyUsage.join(', ')}>
                                    KU: {parsedCsr.requestedExtensions.keyUsage.length}
                                </span>
                            )}
                            {parsedCsr.requestedExtensions.extendedKeyUsage.length > 0 && (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-400 dark:border-gray-600" title={parsedCsr.requestedExtensions.extendedKeyUsage.join(', ')}>
                                    EKU: {parsedCsr.requestedExtensions.extendedKeyUsage.length}
                                </span>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Step 2: Request Profile Selection */}
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
                        <select
                            value={selectedRequestProfile}
                            onChange={(e) => setSelectedRequestProfile(e.target.value)}
                            className={inputClass}
                        >
                            <option value="">-- Select a Request Profile --</option>
                            {requestProfiles.map((p) => (
                                <option key={p.id} value={p.id}>
                                    {p.name}{p.description ? ` — ${p.description}` : ''}
                                </option>
                            ))}
                        </select>
                    </div>
                </div>
            )}

            {/* Step 3: Editable Certificate Fields */}
            {(parsedCsr || tab === 'generate') && selectedRequestProfile && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Step 3: Certificate Fields</h3>
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">Pre-filled from CSR. Edit as needed.</p>
                    </div>
                    <div className="p-4 space-y-4">
                        {/* Subject DN Fields */}
                        <div>
                            <h4 className="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-3 uppercase tracking-wide">Subject DN</h4>
                            <div className="space-y-3">
                                {DN_FIELDS.map((field) => {
                                    const validation = getFieldValidation(field);
                                    const rule = getRuleForField(field);
                                    const borderClass = validation ? statusBorder(validation.status) : 'border-gray-300 dark:border-gray-700';
                                    return (
                                        <div key={field} className="flex items-start gap-3">
                                            <label className="w-12 pt-2 text-xs font-mono font-semibold text-gray-600 dark:text-gray-400 text-right flex-shrink-0">
                                                {field}:
                                            </label>
                                            <div className="flex-1">
                                                <div className="flex items-center">
                                                    <input
                                                        type="text"
                                                        value={subjectFields[field] || ''}
                                                        onChange={(e) => updateSubjectField(field, e.target.value)}
                                                        onBlur={handleFieldBlur}
                                                        className={`flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-900 border ${borderClass} rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500`}
                                                        placeholder={rule?.defaultValue || ''}
                                                        disabled={!!rule?.fixedValue}
                                                    />
                                                    {statusIcon(validation?.status)}
                                                </div>
                                                {/* Validation message */}
                                                {validation?.message && (
                                                    <p className={`text-xs mt-1 ${
                                                        validation.status === 'error' ? 'text-red-800 dark:text-red-400' :
                                                        validation.status === 'warning' ? 'text-yellow-800 dark:text-yellow-400' :
                                                        'text-green-800 dark:text-green-400'
                                                    }`}>
                                                        {validation.message}
                                                    </p>
                                                )}
                                                {/* Rule hint */}
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

                        {/* SAN List */}
                        <div>
                            <h4 className="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-3 uppercase tracking-wide">Subject Alternative Names</h4>
                            <div className="space-y-2">
                                {sanList.map((san, idx) => {
                                    const sanValidation = getSanValidation(idx);
                                    const borderClass = sanValidation ? statusBorder(sanValidation.status) : 'border-gray-300 dark:border-gray-700';
                                    return (
                                        <div key={idx}>
                                            <div className="flex items-center gap-2">
                                                <select
                                                    value={san.type}
                                                    onChange={(e) => updateSan(idx, 'type', e.target.value)}
                                                    onBlur={handleFieldBlur}
                                                    className="px-2 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 w-24 flex-shrink-0"
                                                >
                                                    {SAN_TYPES.map(t => (
                                                        <option key={t} value={t}>{t}</option>
                                                    ))}
                                                </select>
                                                <input
                                                    type="text"
                                                    value={san.value}
                                                    onChange={(e) => updateSan(idx, 'value', e.target.value)}
                                                    onBlur={handleFieldBlur}
                                                    className={`flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-900 border ${borderClass} rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500`}
                                                    placeholder={san.type === 'UPN' ? 'user@domain.example' : `${san.type} value`}
                                                />
                                                {statusIcon(sanValidation?.status)}
                                                <button
                                                    onClick={() => removeSan(idx)}
                                                    className="px-2 py-2 text-sm text-red-800 dark:text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded transition-colors"
                                                    title="Remove SAN"
                                                >
                                                    &#10005;
                                                </button>
                                            </div>
                                            {sanValidation?.message && (
                                                <p className={`text-xs mt-1 ml-28 ${
                                                    sanValidation.status === 'error' ? 'text-red-800 dark:text-red-400' :
                                                    sanValidation.status === 'warning' ? 'text-yellow-800 dark:text-yellow-400' :
                                                    'text-green-800 dark:text-green-400'
                                                }`}>
                                                    {sanValidation.message}
                                                </p>
                                            )}
                                        </div>
                                    );
                                })}
                                <div className="flex flex-wrap items-center gap-2">
                                    <button
                                        onClick={addSan}
                                        className="px-3 py-1.5 text-xs text-blue-800 dark:text-blue-400 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900/30 transition-colors"
                                    >
                                        + Add SAN
                                    </button>
                                    {canAddCnAsSan && (
                                        <button
                                            onClick={addCnAsSan}
                                            title={`Add ${cnValue} as a DNS Subject Alternative Name`}
                                            className="px-3 py-1.5 text-xs text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900/30 transition-colors"
                                        >
                                            + Use CN as DNS SAN
                                            <span className="ml-1.5 font-mono opacity-80">{cnValue}</span>
                                        </button>
                                    )}
                                </div>
                            </div>

                            {/* Clients have not used the CN for hostname verification since RFC 2818
                                was deprecated, and the CA/Browser Forum requires the name in a SAN.
                                A certificate with a hostname CN and no matching DNS SAN therefore
                                looks correct here and is rejected by every browser. Say so before
                                it is issued, not after. */}
                            {canAddCnAsSan && (
                                <p className="text-xs text-yellow-800 dark:text-yellow-400 mt-2">
                                    <span className="font-semibold">{cnValue}</span> is not listed as a DNS SAN.
                                    Clients ignore the Common Name for hostname verification, so this
                                    certificate would not validate for that name.
                                </p>
                            )}
                            {/* SAN rules hint */}
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

            {/* Step 4: Issuance Options Card */}
            {selectedRequestProfile && <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{(parsedCsr || tab === 'generate') ? 'Step 4: ' : ''}Issuance Options</h3>
                </div>
                <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label className={labelClass}>Signing Profile</label>
                        <select
                            value={selectedSigningProfile}
                            onChange={(e) => setSelectedSigningProfile(e.target.value)}
                            className={inputClass}
                        >
                            <option value="">-- Select Signing Profile --</option>
                            {signingProfiles.map((p) => (
                                <option key={p.id || p.name} value={p.id}>
                                    {p.name || p.id}
                                </option>
                            ))}
                        </select>
                    </div>
                    <div>
                        <label className={labelClass}>Certificate Profile</label>
                        <select
                            value={selectedCertProfile}
                            onChange={(e) => setSelectedCertProfile(e.target.value)}
                            className={inputClass}
                        >
                            <option value="">-- Select Certificate Profile --</option>
                            {certProfiles.map((p) => (
                                <option key={p.id || p.name} value={p.id}>
                                    {p.name || p.id}
                                </option>
                            ))}
                        </select>
                    </div>
                    <div>
                        <label className={labelClass}>Not Before</label>
                        <input
                            type="datetime-local"
                            value={notBefore}
                            onChange={(e) => setNotBefore(e.target.value)}
                            className={inputClass}
                        />
                    </div>
                    <div>
                        <label className={labelClass}>Not After</label>
                        <input
                            type="datetime-local"
                            value={notAfter}
                            onChange={(e) => setNotAfter(e.target.value)}
                            className={inputClass}
                        />
                    </div>
                </div>
            </div>}

            {/* Step 5: Submit */}
            <div className="flex items-center gap-4">
                <button
                    onClick={handleSubmit}
                    disabled={loading || !selectedRequestProfile || (tab !== 'generate' && !csrPem.trim()) || !!hasValidationErrors}
                    className="px-6 py-2 text-sm font-semibold bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                    {loading ? 'Submitting...' : (tab === 'generate' ? 'Generate Key & Request Certificate' : 'Request Certificate')}
                </button>
                {hasValidationErrors && (
                    <span className="text-xs text-red-800 dark:text-red-400">Fix validation errors before submitting.</span>
                )}
            </div>

            {/* Result */}
            {error && (
                <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-lg p-4">
                    <p className="text-sm text-red-800 dark:text-red-300">{error}</p>
                </div>
            )}
            {success && (
                <div className="bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded-lg p-4 space-y-3">
                    {success.hasPrivateKey ? (
                        <>
                            <p className="text-sm font-semibold text-green-800 dark:text-green-300">Request submitted with server-generated key pair.</p>
                            <DetailField label="Status" value={success.serial} mono />
                            <div className="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded p-3 mt-2">
                                <p className="text-xs text-yellow-800 dark:text-yellow-300">
                                    The private key is stored encrypted on the server. After the request is approved and issued,
                                    the certificate owner can download the PFX file from the <strong>User Portal</strong> at <code className="bg-gray-900 px-1 rounded">/user/certificates</code>.
                                    PFX export is not available from the admin interface.
                                </p>
                            </div>
                        </>
                    ) : (
                        <>
                            <p className="text-sm font-semibold text-green-800 dark:text-green-300">Certificate request uploaded successfully.</p>
                            <DetailField label="Status" value={success.serial} mono />
                        </>
                    )}
                </div>
            )}

        </div>
    );
};

export default IssueCertificate;
