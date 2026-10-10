import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost } from '../api/client';
import { DetailField } from '@shared/components/cards/DetailField';
import { validateAgainstProfileClient } from '@shared/validation/profileValidation';
import { looksLikeHostname } from '@shared/hostname';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import type { ServerKeyOptions, ValidityCeilingPreflight } from '@shared/generated';
import { describeCeiling, exceedsCeiling, toDatetimeLocalValue } from '../pages/validityCeiling';
import { chooseAlgorithm, findOption, groupRefusals, offeredAlgorithms, offeredSizes, requestKeySize, settleKeyChoice, type KeyChoice } from '../pages/keyOptions';
import { sizeLabel } from '../pages/profiles/keyPolicy';
import { HeldKeyDownload } from './HeldKeyDownload';
import { TypedEntryListEditor, type TypedEntryRowStatus } from '@shared/components/TypedEntryListEditor';
import { SAN_TYPES as SAN_TYPE_DEFS } from '@shared/generalNames';

/**
 * The certificate request form, rendered by both the admin Issue Certificate page and the user
 * portal's Request Certificate page.
 *
 * The two pages once carried separate copies of this flow, and the copies drifted: the admin one
 * gained the validity-ceiling pre-flight, UPN names and the profile-gated submit button, the user
 * one gained the approval badge and the post-submit links, and each fixed its own share of the
 * shared bugs. One component, parameterised by the endpoints it talks to and the `mode` that
 * names which of the two APIs sits behind them, is the only arrangement under which an
 * improvement made for one page reaches the other.
 *
 * The profiles come first, because they decide the rest: the request profile sets the field
 * rules, and the signing profile and certificate profile together decide which keys are
 * accepted. For a key the CA generates the form asks the server which those are (`keyOptions`)
 * and offers only them.
 *
 * `mode` hides exactly what the user API cannot do, nothing more:
 *
 * - The certificate-profile picker lists every profile for an admin. `/api/v1/user` has no
 *   cert-profiles listing, so a user chooses among the ones the request profile designates,
 *   which its listing names in `certProfiles`.
 * - No validity window and no ceiling pre-flight: the user `requests/upload` handler does not
 *   pass `NotBefore`/`NotAfter` to the CSR service, `requests/request-with-key` ignores them, and
 *   there is no `validity-ceiling` endpoint under `/api/v1/user`.
 * - No UPN with a server-generated key: the user `request-with-key` handler builds the CSR with
 *   a local switch that turns any type other than DNS/IP/Email/URI into a DNS name, silently. The
 *   admin handler goes through `SanGeneralNames.Build`, which rejects what it does not know.
 *   A pasted or uploaded CSR is fine either way, because SAN overrides on that path are applied
 *   by the issuance service, which understands UPN.
 *
 * Validation, client-side and server-side, runs against the profile's EFFECTIVE rules after
 * inheritance, because those are the rules issuance applies; a form that checked the row's own
 * rules disagreed with the CA for every inheriting profile. The user list already returns the
 * effective rules (a user never edits a profile). The admin list returns the raw rows, because
 * the profile editor needs them, so in admin mode the form fetches the selected profile's
 * `/resolved` view and validates against that.
 */

// --- Types ---

export type CertificateRequestMode = 'admin' | 'user';

/** The endpoints the form talks to. Same request and response shapes on both APIs. */
export interface CertificateRequestEndpoints {
    /** GET: request profiles the caller may use. */
    requestProfiles: string;
    /** GET: signing profiles the caller may request against. */
    signingProfiles: string;
    /** GET: certificate profiles for the picker. Admin only; the user API has no such listing. */
    certProfiles?: string;
    /** GET `ServerKeyOptions`: the keys the CA may generate under a signing/cert profile pair. */
    keyOptions: (signingProfileId: string, certProfileId: string) => string;
    /** POST `{ pem }`: parse a PEM CSR into subject, SANs and key details. */
    parseCsr: string;
    /** POST `{ requestProfileId, subject, sans }`: validate fields against a request profile. */
    validateAgainstProfile: string;
    /**
     * POST `IssueWithKeyRequest`: server-generated key pair. The key is held by the CA until the
     * certificate is issued and downloaded as PKCS#12 from `pkcs12`; it is not in the response.
     */
    requestWithKey: string;
    /** POST `{ password }` on a request: the certificate, chain and held key as one `.pfx`. */
    pkcs12: (requestId: string) => string;
    /** POST `UploadCsrRequest`: an externally generated CSR. */
    upload: string;
    /** GET, admin only: the effective validity ceiling for a signing/cert profile pair. */
    validityCeiling?: (signingProfileId: string, certProfileId: string) => string;
    /**
     * GET, admin only: a request profile's effective view after inheritance
     * (`EffectiveRequestProfile`). Left out when the list itself already returns effective rules.
     */
    resolvedRequestProfile?: (requestProfileId: string) => string;
}

export interface CertificateRequestFormProps {
    mode: CertificateRequestMode;
    endpoints: CertificateRequestEndpoints;
    /** Where "View requests" on the success panel takes the requester. */
    requestsPath: string;
    /** The form is a tab of a page that draws the heading and the padding itself. */
    embedded?: boolean;
}

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
    requestedExtensions?: CsrRequestedExtensions;
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

/**
 * A request profile as the form uses it. The admin list returns `RequestProfileDto` with the
 * rules already parsed and the id list as a real array; the user list returns the entity's JSON
 * columns as strings. Both are normalised through the parse helpers below on arrival, so the
 * rest of the form sees one shape.
 */
interface RequestProfile {
    id: string;
    name: string;
    description?: string | null;
    subjectDnRules: SubjectDnFieldRule[];
    sanRules: SanRulesObj;
    allowedCertProfileIds: string[];
    defaultCertProfileId?: string | null;
    /** Only the user list returns this: the designated certificate profiles, default first. */
    certProfiles?: CertProfileChoice[];
    requireApproval: boolean;
    /** Only the user list returns this; the admin DTO does not carry it. */
    requiredApprovalCount?: number;
}

interface CertProfileChoice {
    id: string;
    name: string;
}

interface SuccessState {
    message: string;
    requiresApproval: boolean;
    requiredApprovalCount?: number;
    /** The CA holds the generated key for delivery with the certificate. */
    keyHeld?: boolean;
    /** Whether the certificate already exists, so the .pfx can be downloaded here and now. */
    certificateIssued?: boolean;
    csrPem?: string;
    requestId?: string;
    subject?: string;
}

// --- Constants ---

const DN_FIELDS = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
// UPN is a Microsoft otherName (1.3.6.1.4.1.311.20.2.3) and is how Windows maps a smart-card
// logon certificate to an Active Directory account. Unlike the others it names a principal rather
// than a network endpoint, so a request profile has to list it in allowedTypes before it can be
// used — see RequestProfiles.
const SAN_TYPES = SAN_TYPE_DEFS.map(t => t.value);

const TAB_ACTIVE = 'bg-accent-soft text-accent-ink border border-accent/40';
const TAB_IDLE = 'bg-sunken text-ink-muted border border-line-strong hover:bg-hover';
const CARD = 'bg-raised border border-line rounded-lg overflow-hidden';
const CARD_HEAD = 'px-4 py-3 border-b border-line';
const CARD_TITLE = 'text-sm font-semibold text-ink';
const FIELD_INPUT = 'flex-1 px-3 py-2 bg-raised border rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent';

// --- Helpers ---

/**
 * Lower-camels every object key, recursively. Rules the server seeds at bootstrap are serialised
 * with default System.Text.Json options and stored with PascalCase keys (`Field`, `Requirement`,
 * `FixedValue`, `Regex`, and the SAN rule objects likewise), while rules saved from the console
 * are camelCase; the profile list and the `/resolved` view pass the stored text through as is.
 * Everything here matches on `rule.field`, so a seeded profile showed no hints and reported
 * "No rule defined for this field" for every field it did have a rule for. One shape on arrival,
 * whatever wrote it. The SAN `rules` map is keyed by SAN type (`DNS`, `IP`), which must keep
 * its case, so that one level is left alone.
 */
function lowerCamelKeys(value: any, keepKeysAt: string[] = []): any {
    if (Array.isArray(value)) return value.map(v => lowerCamelKeys(v, keepKeysAt));
    if (!value || typeof value !== 'object') return value;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) {
        const key = k.charAt(0).toLowerCase() + k.slice(1);
        out[key] = keepKeysAt.includes(key) ? keepMapKeys(v) : lowerCamelKeys(v, keepKeysAt);
    }
    return out;
}

/** A map whose keys are data (SAN types): keys kept, values normalised. */
function keepMapKeys(value: any): any {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(value)) out[k] = lowerCamelKeys(v);
    return out;
}

function parseRules(raw: any): SubjectDnFieldRule[] {
    if (Array.isArray(raw)) return lowerCamelKeys(raw);
    if (typeof raw === 'string') { try { return lowerCamelKeys(JSON.parse(raw)); } catch { return []; } }
    return [];
}

function parseSanRules(raw: any): SanRulesObj {
    const defaults: SanRulesObj = { allowedTypes: SAN_TYPES, required: false, rules: {} };
    if (!raw) return defaults;
    if (typeof raw === 'string') { try { return { ...defaults, ...lowerCamelKeys(JSON.parse(raw), ['rules']) }; } catch { return defaults; } }
    return { ...defaults, ...lowerCamelKeys(raw, ['rules']) };
}

/**
 * Reads a field that may arrive as a real array or as a JSON array string. Entity columns that
 * store JSON come back as strings; the admin DTO deserialises them first. Returning [] for
 * anything unparseable is safe here: the caller falls back to no explicit profile. Indexing the
 * raw string as an array once sent '[' as a certificate profile id.
 */
function parseIdList(value: unknown): string[] {
    if (Array.isArray(value)) return value.map(String).filter(Boolean);
    if (typeof value !== 'string' || !value.trim()) return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
    } catch {
        return [];
    }
}

/**
 * One shape from three sources: the admin list (parsed rules, real arrays), the user list
 * (JSON-string columns, with the effective rules also under `effective*`), and the admin
 * `/resolved` view (JSON-string columns, `sourceProfileId` in place of `id`). The effective
 * rules win wherever the payload names them.
 */
function normaliseRequestProfile(p: any, id?: string): RequestProfile {
    return {
        ...p,
        id: p.id || id || p.sourceProfileId,
        subjectDnRules: parseRules(p.effectiveSubjectDnRules ?? p.subjectDnRules),
        sanRules: parseSanRules(p.effectiveSanRules ?? p.sanRules),
        allowedCertProfileIds: parseIdList(p.allowedCertProfileIds),
        certProfiles: Array.isArray(p.certProfiles) ? p.certProfiles : undefined,
        requireApproval: !!p.requireApproval,
        requiredApprovalCount: typeof p.requiredApprovalCount === 'number' ? p.requiredApprovalCount : undefined,
    };
}

// Hands the CSR to the browser as a file. The private key never comes this way: the CA holds it
// until the certificate is issued and it leaves inside the .pfx.
function downloadText(text: string, filename: string, mimeType: string) {
    const url = URL.createObjectURL(new Blob([text], { type: mimeType }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function statusIcon(status?: string) {
    switch (status) {
        case 'valid': return <span className="text-ok text-sm ml-2" title="Valid">&#10003;</span>;
        case 'warning': return <span className="text-warn text-sm ml-2" title="Warning">&#9888;</span>;
        case 'error': return <span className="text-crit text-sm ml-2" title="Error">&#10007;</span>;
        default: return null;
    }
}

function statusBorder(status?: string) {
    switch (status) {
        case 'valid': return 'border-ok/40';
        case 'warning': return 'border-warn/40';
        case 'error': return 'border-crit/40';
        default: return 'border-line';
    }
}

function statusText(status: string) {
    return status === 'error' ? 'text-crit'
        : status === 'warning' ? 'text-warn'
        : 'text-ok';
}

// --- Component ---

export const CertificateRequestForm: React.FC<CertificateRequestFormProps> = ({ mode, endpoints, requestsPath, embedded }) => {
    // What the user API leaves out; see the header comment for the reason behind each.
    const listsCertProfiles = mode === 'admin' && !!endpoints.certProfiles;
    const showValidityWindow = mode === 'admin';
    const showCeilingPreflight = mode === 'admin' && !!endpoints.validityCeiling;
    const allowUpnWithGeneratedKey = mode === 'admin';

    // CSR input
    const [tab, setTab] = useState<'paste' | 'upload' | 'generate'>('paste');
    const [csrPem, setCsrPem] = useState('');
    const [fileName, setFileName] = useState('');

    // Parsed CSR data
    const [parsedCsr, setParsedCsr] = useState<ParseCsrResponse | null>(null);
    const [parseError, setParseError] = useState<NoticeInput | null>(null);
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
    // The effective validity ceiling for the selected profile pair, and which layer sets it.
    // Null until the first answer arrives, and again whenever a profile changes — "unknown" must
    // not render as "no ceiling", which would be the one reading that is actively misleading.
    const [ceiling, setCeiling] = useState<ValidityCeilingPreflight | null>(null);

    // Generate key pair: the keys the chosen profiles accept, and the one picked among them.
    const [keyOptions, setKeyOptions] = useState<ServerKeyOptions | null>(null);
    const [keyOptionsError, setKeyOptionsError] = useState<NoticeInput | null>(null);
    const [keyChoice, setKeyChoice] = useState<KeyChoice | null>(null);

    // Submit state
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [success, setSuccess] = useState<SuccessState | null>(null);

    // --- Initial data load ---
    useEffect(() => {
        apiGet<any>(endpoints.signingProfiles)
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setSigningProfiles(items);
                // The profile flagged as default is the one most requests want; failing that,
                // the first, so the button is not disabled for want of a choice nobody made.
                const preferred = items.find((p: any) => p.isDefault) || items[0];
                if (preferred) setSelectedSigningProfile(preferred.id || preferred.name || '');
            })
            .catch(() => {});

        if (endpoints.certProfiles) {
            apiGet<any>(endpoints.certProfiles)
                .then((data) => {
                    const items = Array.isArray(data) ? data : (data.items || []);
                    setCertProfiles(items);
                    if (items.length > 0) setSelectedCertProfile(items[0].id || items[0].name || '');
                })
                .catch(() => {});
        }

        apiGet<any>(endpoints.requestProfiles)
            .then((data) => {
                const items = Array.isArray(data) ? data : (data.items || []);
                setRequestProfiles(items.map(normaliseRequestProfile));
            })
            .catch(() => {});

        // <input type="datetime-local"> reads its value as LOCAL time, so it must be seeded
        // with local wall-clock components. toISOString() returns UTC: seeding from it put a
        // UTC clock reading into a local-time field, so the form opened pre-filled with a
        // notBefore one UTC-offset in the future, and the certificate was issued starting
        // then — invalid to every relying party until that time arrived. The conversion now
        // lives in validityCeiling.ts, where it is covered, because the ceiling's `max`
        // attribute is read the same way and would be wrong in the same direction.
        const now = new Date();
        const oneYear = new Date(now);
        oneYear.setFullYear(oneYear.getFullYear() + 1);
        setNotBefore(toDatetimeLocalValue(now));
        setNotAfter(toDatetimeLocalValue(oneYear));
    }, [endpoints.signingProfiles, endpoints.certProfiles, endpoints.requestProfiles]);

    // The selected profile as the form reasons about it: its effective view when the API offers
    // one and it has arrived, the listed row until then (and where the list is already effective).
    const listedProfile = requestProfiles.find(p => p.id === selectedRequestProfile);
    const [resolvedProfile, setResolvedProfile] = useState<RequestProfile | null>(null);

    useEffect(() => {
        if (!endpoints.resolvedRequestProfile || !selectedRequestProfile) {
            setResolvedProfile(null);
            return;
        }
        let cancelled = false;
        apiGet<any>(endpoints.resolvedRequestProfile(selectedRequestProfile))
            .then((data) => { if (!cancelled) setResolvedProfile(normaliseRequestProfile(data, selectedRequestProfile)); })
            // The row's own rules stand in; the server's validate call, which resolves for
            // itself, still gates submission with the effective ones.
            .catch(() => { if (!cancelled) setResolvedProfile(null); });
        return () => { cancelled = true; };
    }, [endpoints.resolvedRequestProfile, selectedRequestProfile]);

    const selectedProfileObj = resolvedProfile && resolvedProfile.id === selectedRequestProfile
        ? resolvedProfile
        : listedProfile;

    // The certificate profiles the picker offers: every one for an admin, the ones the request
    // profile designates for a user.
    const certProfileChoices: CertProfileChoice[] = listsCertProfiles
        ? certProfiles.map((p: any) => ({ id: p.id, name: p.name || p.id }))
        : (selectedProfileObj?.certProfiles ?? []);
    const effectiveCertProfileId = selectedCertProfile;

    // A request profile that designates a certificate profile pre-selects it in the picker, so
    // the operator does not have to know which of the two lists the pairing lives in. Where the
    // picker holds only the designated ones, it never keeps a choice from another request profile.
    useEffect(() => {
        const wanted = selectedProfileObj?.defaultCertProfileId || selectedProfileObj?.allowedCertProfileIds[0];
        if (wanted && certProfileChoices.some(p => p.id === wanted)) setSelectedCertProfile(wanted);
        else if (!listsCertProfiles) setSelectedCertProfile(certProfileChoices[0]?.id ?? '');
    }, [selectedRequestProfile, certProfiles]); // eslint-disable-line react-hooks/exhaustive-deps

    // --- Validity ceiling pre-flight ---
    // Re-asked whenever the profile pair changes, because both selections feed the answer: the
    // signing profile determines the issuing CA and therefore the space, and the cert profile
    // supplies the baseline maximum. Deliberately NOT re-asked as notBefore is typed — the server
    // measures the space ceiling from notBefore, but a request per keystroke to move a number by
    // a few hours is not worth it, and the default start is what nearly every request uses.
    useEffect(() => {
        if (!showCeilingPreflight || !selectedSigningProfile || !effectiveCertProfileId) {
            setCeiling(null);
            return;
        }
        let cancelled = false;
        apiGet<ValidityCeilingPreflight>(endpoints.validityCeiling!(selectedSigningProfile, effectiveCertProfileId))
            .then((data) => { if (!cancelled) setCeiling(data); })
            // Silently unknown rather than an error banner: the pre-flight is an aid, and the
            // server still enforces the real ceiling at issuance either way. An operator who is
            // told nothing is no worse off than they were before this existed; one shown a red
            // failure for an advisory call would reasonably stop trusting the form.
            .catch(() => { if (!cancelled) setCeiling(null); });
        return () => { cancelled = true; };
    }, [showCeilingPreflight, endpoints.validityCeiling, selectedSigningProfile, effectiveCertProfileId]);

    const ceilingNotice = ceiling ? describeCeiling(ceiling) : null;
    const notAfterExceedsCeiling = exceedsCeiling(notAfter, ceiling);

    // --- Keys the profiles accept ---
    // Asked of the server, which runs the checks submission and issuance run, whenever the
    // profile pair changes while the CA is to generate the key.
    const keyOptionsWanted = tab === 'generate' && !!selectedSigningProfile && !!effectiveCertProfileId;
    useEffect(() => {
        setKeyOptions(null);
        setKeyOptionsError(null);
        if (!keyOptionsWanted) return;
        let cancelled = false;
        apiGet<ServerKeyOptions>(endpoints.keyOptions(selectedSigningProfile, effectiveCertProfileId))
            .then((data) => {
                if (cancelled) return;
                setKeyOptions(data);
                setKeyChoice((current) => settleKeyChoice(data.options, current));
            })
            .catch((err) => { if (!cancelled) setKeyOptionsError(errorNotice(err, 'Could not check which keys these profiles accept')); });
        return () => { cancelled = true; };
    }, [keyOptionsWanted, endpoints.keyOptions, selectedSigningProfile, effectiveCertProfileId]);

    const keyOptionsLoading = keyOptionsWanted && !keyOptions && !keyOptionsError;
    const offeredKeys = keyOptions?.options ?? [];
    const chosenKey = findOption(offeredKeys, keyChoice);
    const chosenKeySizes = keyChoice ? offeredSizes(offeredKeys, keyChoice.algorithm) : [];

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
            const result = await apiPost<ParseCsrResponse>(endpoints.parseCsr, { pem });
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
            setParseError(errorNotice(err, 'Failed to parse CSR'));
        } finally {
            setParsing(false);
        }
    }, [endpoints.parseCsr]);

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
    const hasFieldData = !!parsedCsr || tab === 'generate';
    // True when subject/sans changed since the last server confirmation; cleared on blur after
    // the server call fires so a tab-through that doesn't actually edit anything stays free.
    const [pendingServerConfirm, setPendingServerConfirm] = useState(false);

    const confirmAgainstServer = useCallback(async (profileId: string) => {
        if (!profileId || !hasFieldData) return;
        setValidating(true);
        try {
            const result = await apiPost<ValidateResponse>(endpoints.validateAgainstProfile, {
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
    }, [endpoints.validateAgainstProfile, hasFieldData, subjectFields, sanList]);

    // Per-keystroke client-side validation. Pure synchronous JS, no network.
    useEffect(() => {
        if (!selectedRequestProfile || !hasFieldData) {
            setValidationResult(null);
            return;
        }
        if (!selectedProfileObj) return;
        const result = validateAgainstProfileClient(
            subjectFields,
            sanList.filter(s => s.value.trim()),
            selectedProfileObj.subjectDnRules,
            selectedProfileObj.sanRules,
        );
        setValidationResult(result);
        setPendingServerConfirm(true); // mark for next blur to confirm against server
    }, [subjectFields, sanList, selectedRequestProfile, parsedCsr, selectedProfileObj, hasFieldData]);

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
        reader.onload = (ev) => {
            setCsrPem(ev.target?.result as string || '');
        };
        reader.readAsText(file);
    };

    // --- SAN helpers ---
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

    /**
     * The server's result for row `idx`. The validate call sends only the rows with a value, so
     * the results line up with those; a blank row has no result.
     */
    const getSanValidation = (idx: number): SanValidationResult | undefined => {
        if (!sanList[idx]?.value.trim()) return undefined;
        const filledIndex = sanList.slice(0, idx).filter(s => s.value.trim()).length;
        return validationResult?.sanResults[filledIndex];
    };

    const getRuleForField = (field: string): SubjectDnFieldRule | undefined => {
        return selectedProfileObj?.subjectDnRules?.find(r => r.field === field);
    };

    // The SAN types this request can carry. UPN is withheld only where the API behind the
    // form would sign it as a DNS name without saying so.
    const upnBlocked = tab === 'generate' && !allowUpnWithGeneratedKey;
    const sanTypes = upnBlocked ? SAN_TYPES.filter(t => t !== 'UPN') : SAN_TYPES;
    const blockedUpnRows = upnBlocked ? sanList.filter(s => s.type === 'UPN' && s.value.trim()) : [];

    /** A row's status for the SAN editor: a blocked UPN first, then the server's verdict. */
    const sanRowStatus = (san: SanEntry, idx: number): TypedEntryRowStatus | undefined => {
        if (upnBlocked && san.type === 'UPN') {
            return { status: 'error', message: 'A UPN cannot be requested with a server-generated key from here. Paste or upload a CSR instead, or remove this name.' };
        }
        const result = getSanValidation(idx);
        return result ? { status: result.status, message: result.message ?? undefined } : undefined;
    };

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

    // --- Submit ---
    const hasValidationErrors = !!validationResult && !validationResult.valid;
    // Where the picker holds only what the request profile designates, a request profile that
    // designates none cannot be used from here at all.
    const requestProfileLacksCertProfile = !listsCertProfiles && !!selectedProfileObj && certProfileChoices.length === 0;
    // Both profiles are required by the server; without them the click only produced an error
    // banner after the fact. Name what is missing so the button's disabled state explains itself.
    const missingProfiles = [
        !selectedSigningProfile ? 'a signing profile' : null,
        !selectedCertProfile && !requestProfileLacksCertProfile ? 'a certificate profile' : null,
    ].filter(Boolean) as string[];

    const canSubmit = !loading
        && !!selectedRequestProfile
        && (tab === 'generate' ? !!chosenKey : !!csrPem.trim())
        && !hasValidationErrors
        && missingProfiles.length === 0
        && !requestProfileLacksCertProfile
        && blockedUpnRows.length === 0;

    const resetForm = () => {
        setCsrPem('');
        setFileName('');
        setParsedCsr(null);
        setSubjectFields({});
        setSanList([]);
        setSelectedRequestProfile('');
        setValidationResult(null);
    };

    const handleSubmit = async () => {
        if (!selectedRequestProfile) { setError('Please select a request profile.'); return; }
        if (tab !== 'generate' && !csrPem.trim()) { setError('Please provide a CSR.'); return; }
        if (!selectedSigningProfile) { setError('Please select a signing profile.'); return; }
        if (requestProfileLacksCertProfile) {
            setError('This request profile has no certificate profile assigned, so it cannot be used. Ask an administrator to set one.');
            return;
        }
        if (!effectiveCertProfileId) { setError('Please select a certificate profile.'); return; }
        if (tab === 'generate' && (!keyChoice || !chosenKey)) { setError('Choose a key the selected profiles accept.'); return; }
        if (blockedUpnRows.length > 0) {
            setError('A UPN name cannot be requested with a server-generated key from here. Paste or upload a CSR instead.');
            return;
        }

        setLoading(true);
        setError(null);
        setSuccess(null);

        const requiresApproval = !!selectedProfileObj?.requireApproval;
        const requiredApprovalCount = selectedProfileObj?.requiredApprovalCount;
        const validity = showValidityWindow ? {
            notBefore: notBefore ? new Date(notBefore).toISOString() : undefined,
            notAfter: notAfter ? new Date(notAfter).toISOString() : undefined,
        } : {};

        try {
            const subject: Record<string, string> = {};
            for (const [k, v] of Object.entries(subjectFields)) {
                if (v.trim()) subject[k] = v.trim();
            }
            const sans = sanList
                .filter(s => s.value.trim())
                .map(s => ({ type: s.type, value: s.value.trim() }));

            if (tab === 'generate') {
                // Server-side key generation flow — creates request, does NOT issue immediately
                if (Object.keys(subject).length === 0) {
                    setError('Please fill in at least one subject field (e.g., CN).');
                    setLoading(false);
                    return;
                }

                const created = await apiPost<any>(endpoints.requestWithKey, {
                    subject,
                    sans,
                    keyAlgorithm: keyChoice!.algorithm,
                    keySize: requestKeySize(keyChoice!),
                    certProfileId: effectiveCertProfileId,
                    signingProfileId: selectedSigningProfile,
                    ...validity,
                });

                const certificateIssued = !!created?.certificateIssued;
                setSuccess({
                    message: certificateIssued
                        ? 'The certificate has been issued. Download it together with its private key below.'
                        : mode === 'admin'
                            ? 'Request submitted with a server-generated key pair. Approve and issue it from the Requests page.'
                            : 'Your certificate request has been submitted with a server-generated key pair.',
                    requiresApproval,
                    requiredApprovalCount,
                    keyHeld: created?.keyHeld !== false,
                    certificateIssued,
                    csrPem: created?.csr,
                    requestId: created?.requestId,
                    subject: subject['CN'] || Object.values(subject)[0],
                });
            } else {
                // Standard CSR upload flow
                await apiPost<any>(endpoints.upload, {
                    pem: csrPem.trim(),
                    signingProfileId: selectedSigningProfile,
                    certificateProfileId: effectiveCertProfileId,
                    subjectOverrides: Object.keys(subject).length > 0 ? subject : undefined,
                    sanOverrides: sans.length > 0 ? sans : undefined,
                    ...validity,
                });

                setSuccess({
                    message: mode === 'admin'
                        ? (requiresApproval
                            ? 'Certificate request uploaded. It needs approval before it can be issued from the Requests page.'
                            : 'Certificate request uploaded. Issue it from the Requests page.')
                        : (requiresApproval
                            ? 'Your certificate request has been submitted and will be reviewed by an administrator.'
                            : 'Your certificate request has been submitted and is being processed.'),
                    requiresApproval,
                    requiredApprovalCount,
                });
            }
            resetForm();
        } catch (err: any) {
            setError(errorNotice(err, 'Certificate request failed'));
        } finally {
            setLoading(false);
        }
    };

    const dismissSuccess = () => setSuccess(null);

    const showFields = (!!parsedCsr || tab === 'generate') && !!selectedRequestProfile;

    return (
        <div className={embedded ? 'space-y-4 sm:space-y-6' : 'p-3 sm:p-6 space-y-4 sm:space-y-6'}>
            {!embedded && <h1 className="text-xl font-semibold text-ink">Request Certificate</h1>}

            {/* Step 1: Profiles */}
            <div className={CARD}>
                <div className={CARD_HEAD}>
                    <h3 className={CARD_TITLE}>Step 1: Profiles</h3>
                    <p className="text-xs text-ink-muted mt-1">The request profile sets the rules for the names. The signing profile and the certificate profile decide which keys are accepted.</p>
                </div>
                <div className="p-4 space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label htmlFor="request-profile" className={labelClass}>Request Profile</label>
                            <select
                                id="request-profile"
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
                        <div>
                            <label htmlFor="signing-profile" className={labelClass}>Signing Profile</label>
                            <select
                                id="signing-profile"
                                value={selectedSigningProfile}
                                onChange={(e) => setSelectedSigningProfile(e.target.value)}
                                className={inputClass}
                            >
                                <option value="">-- Select Signing Profile --</option>
                                {signingProfiles.map((p) => (
                                    <option key={p.id || p.name} value={p.id}>
                                        {p.name || p.id}{p.isDefault ? ' (default)' : ''}
                                    </option>
                                ))}
                            </select>
                            <FieldHint className="mt-1">Names the issuing CA.</FieldHint>
                        </div>
                        <div>
                            <label htmlFor="cert-profile" className={labelClass}>Certificate Profile</label>
                            <select
                                id="cert-profile"
                                value={selectedCertProfile}
                                onChange={(e) => setSelectedCertProfile(e.target.value)}
                                disabled={!listsCertProfiles && !selectedRequestProfile}
                                className={inputClass}
                            >
                                <option value="">-- Select Certificate Profile --</option>
                                {certProfileChoices.map((p) => (
                                    <option key={p.id} value={p.id}>{p.name}</option>
                                ))}
                            </select>
                            {!listsCertProfiles && (
                                <FieldHint className="mt-1">The ones the request profile allows.</FieldHint>
                            )}
                        </div>
                    </div>
                    {selectedProfileObj?.requireApproval && (
                        <div className="flex flex-wrap gap-2">
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-warn-soft text-warn border border-warn/40">
                                Requires Approval{selectedProfileObj.requiredApprovalCount ? ` (${selectedProfileObj.requiredApprovalCount})` : ''}
                            </span>
                        </div>
                    )}
                    {requestProfileLacksCertProfile && (
                        <FieldHint tone="warn">This request profile has no certificate profile assigned, so it cannot be used from here. Ask an administrator to set one.</FieldHint>
                    )}
                </div>
            </div>

            {/* Step 2: the key, in a CSR made elsewhere or generated by the CA */}
            <div className={CARD}>
                <div className={CARD_HEAD}>
                    <h3 className={CARD_TITLE}>Step 2: Key</h3>
                </div>
                <div className="p-4 space-y-4">
                    <div className="flex gap-2">
                        <button onClick={() => setTab('paste')} className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'paste' ? TAB_ACTIVE : TAB_IDLE}`}>
                            Paste CSR
                        </button>
                        <button onClick={() => setTab('upload')} className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'upload' ? TAB_ACTIVE : TAB_IDLE}`}>
                            Upload CSR File
                        </button>
                        <button onClick={() => setTab('generate')} className={`px-4 py-2 text-sm rounded transition-colors ${tab === 'generate' ? TAB_ACTIVE : TAB_IDLE}`}>
                            Generate Key Pair
                        </button>
                    </div>

                    {tab === 'paste' && (
                        <div>
                            <label className={labelClass}>PEM-encoded CSR</label>
                            <textarea
                                value={csrPem}
                                onChange={(e) => setCsrPem(e.target.value)}
                                placeholder={"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}
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
                                className="block w-full text-sm text-ink-muted file:mr-4 file:py-2 file:px-4 file:rounded file:border file:border-line-strong file:text-sm file:bg-sunken file:text-ink hover:file:bg-hover"
                            />
                            {fileName && (
                                <p className="mt-2 text-xs text-ink-muted">Loaded: {fileName}</p>
                            )}
                            {csrPem && (
                                <pre className="mt-2 p-2 bg-sunken border border-line rounded text-ink-muted data-mono max-h-40 overflow-auto">
                                    {csrPem.substring(0, 500)}{csrPem.length > 500 ? '...' : ''}
                                </pre>
                            )}
                        </div>
                    )}

                    {tab === 'generate' && (
                        <div className="space-y-4">
                            {!keyOptionsWanted && (
                                <FieldHint>Choose a signing profile and a certificate profile in step 1. The keys they accept are then listed here.</FieldHint>
                            )}
                            {keyOptionsLoading && (
                                <p className="text-xs text-ink-muted">Checking which keys these profiles accept...</p>
                            )}
                            {keyOptionsError && (
                                <div className="bg-crit-soft border border-crit/40 rounded p-3">
                                    <InlineNotice notice={keyOptionsError} variant="line" />
                                </div>
                            )}
                            {keyOptions && offeredKeys.length === 0 && (
                                <FieldHint tone="warn">
                                    Signing profile <span className="font-semibold">{keyOptions.signingProfileName}</span> and certificate profile <span className="font-semibold">{keyOptions.certProfileName}</span> accept no key the CA can generate. Choose other profiles in step 1, or paste or upload a CSR made elsewhere.
                                </FieldHint>
                            )}
                            {keyOptions && keyChoice && offeredKeys.length > 0 && (
                                <>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label htmlFor="key-algorithm" className={labelClass}>Key Algorithm</label>
                                            <select
                                                id="key-algorithm"
                                                value={keyChoice.algorithm}
                                                onChange={(e) => setKeyChoice(chooseAlgorithm(offeredKeys, e.target.value))}
                                                className={inputClass}
                                            >
                                                {offeredAlgorithms(offeredKeys).map(a => (
                                                    <option key={a} value={a}>{a}</option>
                                                ))}
                                            </select>
                                        </div>
                                        {chosenKeySizes.length > 0 && (
                                            <div>
                                                <label htmlFor="key-size" className={labelClass}>{keyChoice.algorithm === 'ECDSA' ? 'Curve' : 'Key Size'}</label>
                                                <select
                                                    id="key-size"
                                                    value={keyChoice.keySize ?? ''}
                                                    onChange={(e) => setKeyChoice({ algorithm: keyChoice.algorithm, keySize: e.target.value })}
                                                    className={inputClass}
                                                >
                                                    {chosenKeySizes.map(s => (
                                                        <option key={s} value={s}>{sizeLabel(s)}</option>
                                                    ))}
                                                </select>
                                                {keyChoice.algorithm === 'RSA' && (keyChoice.keySize === '7680' || keyChoice.keySize === '8192') && (
                                                    <p className="text-xs text-warn mt-1">
                                                        ⚠ High-compute RSA — key generation may take 30+ seconds.
                                                    </p>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                    <FieldHint>
                                        Only the keys that signing profile <span className="font-semibold">{keyOptions.signingProfileName}</span> and certificate profile <span className="font-semibold">{keyOptions.certProfileName}</span> accept are offered.
                                        {chosenKey && <> The CA generates the key and signs the request with <span className="data-mono">{chosenKey.signatureAlgorithm}</span>.</>}
                                    </FieldHint>
                                </>
                            )}
                            {keyOptions && keyOptions.refused.length > 0 && (
                                <details className="text-xs text-ink-muted" open={offeredKeys.length === 0}>
                                    <summary className="cursor-pointer">Keys not offered ({keyOptions.refused.length})</summary>
                                    <ul className="mt-2 space-y-1">
                                        {groupRefusals(keyOptions.refused).map(g => (
                                            <li key={g.reason}><span className="text-ink">{g.keys.join(', ')}</span>: {g.reason}</li>
                                        ))}
                                    </ul>
                                </details>
                            )}
                            <FieldHint tone="warn">The CA holds the private key only until the certificate is issued and you download the .pfx; it is deleted on delivery.</FieldHint>
                        </div>
                    )}

                    {/* Parse status */}
                    {parsing && (
                        <p className="text-xs text-ink-muted">Parsing CSR...</p>
                    )}
                    {parseError && (
                        <div className="bg-crit-soft border border-crit/40 rounded p-3">
                            <InlineNotice notice={parseError} variant="line" />
                        </div>
                    )}

                    {/* Key info badges */}
                    {parsedCsr && (
                        <div className="flex flex-wrap gap-2">
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-info-soft text-info border border-info/40">
                                {parsedCsr.keyAlgorithm} {parsedCsr.keySize && `(${parsedCsr.keySize})`}
                            </span>
                            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-accent-soft text-accent-ink border border-accent/40">
                                {parsedCsr.signatureAlgorithm}
                            </span>
                            {parsedCsr.valid ? (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-ok-soft text-ok border border-ok/40">
                                    Signature Valid
                                </span>
                            ) : (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-crit-soft text-crit border border-crit/40">
                                    Signature Invalid
                                </span>
                            )}
                            {(parsedCsr.requestedExtensions?.keyUsage?.length ?? 0) > 0 && (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-sunken text-ink border border-line-strong" title={parsedCsr.requestedExtensions!.keyUsage.join(', ')}>
                                    KU: {parsedCsr.requestedExtensions!.keyUsage.length}
                                </span>
                            )}
                            {(parsedCsr.requestedExtensions?.extendedKeyUsage?.length ?? 0) > 0 && (
                                <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-sunken text-ink border border-line-strong" title={parsedCsr.requestedExtensions!.extendedKeyUsage.join(', ')}>
                                    EKU: {parsedCsr.requestedExtensions!.extendedKeyUsage.length}
                                </span>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Step 3: Editable Certificate Fields */}
            {showFields && (
                <div className={CARD}>
                    <div className={`${CARD_HEAD} flex items-start justify-between gap-3`}>
                        <div>
                            <h3 className={CARD_TITLE}>Step 3: Certificate Fields</h3>
                            <p className="text-xs text-ink-muted mt-1">{parsedCsr ? 'Pre-filled from CSR. Edit as needed.' : 'The server builds the CSR from these fields.'}</p>
                        </div>
                        {validating && <span className="text-xs text-ink-muted">Validating...</span>}
                        {validationResult && !validating && (
                            validationResult.valid
                                ? <span className="text-xs text-ok">All checks passed</span>
                                : <span className="text-xs text-crit">Validation errors found</span>
                        )}
                    </div>
                    <div className="p-4 space-y-4">
                        {/* Subject DN Fields */}
                        <div>
                            <h4 className="text-xs font-semibold text-ink mb-3 uppercase tracking-wide">Subject DN</h4>
                            <div className="space-y-3">
                                {DN_FIELDS.map((field) => {
                                    const validation = getFieldValidation(field);
                                    const rule = getRuleForField(field);
                                    return (
                                        <div key={field} className="flex items-start gap-3">
                                            <label className="w-12 pt-2 data-mono font-semibold text-ink-muted text-right flex-shrink-0">
                                                {field}:
                                            </label>
                                            <div className="flex-1">
                                                <div className="flex items-center">
                                                    <input
                                                        type="text"
                                                        value={subjectFields[field] || ''}
                                                        onChange={(e) => updateSubjectField(field, e.target.value)}
                                                        onBlur={handleFieldBlur}
                                                        className={`${FIELD_INPUT} ${statusBorder(validation?.status)}`}
                                                        placeholder={rule?.defaultValue || ''}
                                                        disabled={!!rule?.fixedValue}
                                                    />
                                                    {statusIcon(validation?.status)}
                                                </div>
                                                {/* Validation message */}
                                                {validation?.message && (
                                                    <p className={`text-xs mt-1 ${statusText(validation.status)}`}>
                                                        {validation.message}
                                                    </p>
                                                )}
                                                {/* Rule hint */}
                                                {rule && !validation?.message && (
                                                    <p className="text-xs mt-1 text-ink-muted">
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
                            <h4 className="text-xs font-semibold text-ink mb-3 uppercase tracking-wide">Subject Alternative Names</h4>
                            <div>
                                {/* Validation is the server's (validate-against-profile on blur), so the
                                    editor's own per-type checks are off and its status comes from there. */}
                                <TypedEntryListEditor
                                    aria-label="Subject Alternative Names"
                                    value={sanList}
                                    onChange={setSanList}
                                    types={SAN_TYPE_DEFS}
                                    offeredTypes={sanTypes}
                                    defaultType="DNS"
                                    validate={false}
                                    rowStatus={sanRowStatus}
                                    onBlur={handleFieldBlur}
                                    addLabel="+ Add SAN"
                                    actions={canAddCnAsSan && (
                                        <button
                                            type="button"
                                            onClick={addCnAsSan}
                                            title={`Add ${cnValue} as a DNS Subject Alternative Name`}
                                            className="px-3 py-1.5 text-xs text-ok border border-ok/40 rounded hover:bg-ok-soft transition-colors"
                                        >
                                            + Use CN as DNS SAN
                                            <span className="ml-1.5 font-mono opacity-80">{cnValue}</span>
                                        </button>
                                    )}
                                />
                            </div>

                            {/* Clients have not used the CN for hostname verification since RFC 2818
                                was deprecated, and the CA/Browser Forum requires the name in a SAN.
                                A certificate with a hostname CN and no matching DNS SAN therefore
                                looks correct here and is rejected by every browser. Say so before
                                it is issued, not after. */}
                            {canAddCnAsSan && (
                                <p className="text-xs text-warn mt-2">
                                    <span className="font-semibold">{cnValue}</span> is not listed as a DNS SAN.
                                    Clients ignore the Common Name for hostname verification, so this
                                    certificate would not validate for that name.
                                </p>
                            )}
                            {/* SAN rules hint */}
                            {selectedProfileObj?.sanRules && (
                                <p className="text-xs text-ink-muted mt-2">
                                    Allowed types: {selectedProfileObj.sanRules.allowedTypes?.join(', ') || 'Any'}
                                    {selectedProfileObj.sanRules.required ? ' | At least one SAN required' : ''}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Validity window */}
            {showValidityWindow && (
                <div className={CARD}>
                    <div className={CARD_HEAD}>
                        <h3 className={CARD_TITLE}>Step {showFields ? 4 : 3}: Validity</h3>
                    </div>
                    <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
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
                                // Bound to the effective ceiling so the picker cannot offer a date
                                // issuance would shorten. Browsers differ on whether they block an
                                // out-of-range value or merely flag it, so the explicit check below
                                // still runs — max is a convenience, not the enforcement.
                                max={ceilingNotice?.maxInputValue || undefined}
                                className={inputClass}
                            />
                            {ceilingNotice && (
                                <p className={`text-[11px] mt-1 ${ceilingNotice.tone === 'warn'
                                    ? 'text-warn'
                                    : 'text-ink-muted'}`}>
                                    {ceilingNotice.text}
                                </p>
                            )}
                            {notAfterExceedsCeiling && ceiling && (
                                <p className="text-[11px] mt-1 text-crit">
                                    {ceiling.spaceBehavior === 'Refuse' && ceiling.spaceCeilingApplies && ceiling.resolution.boundBy === 'Space'
                                        ? 'This exceeds the ceiling above and will be refused.'
                                        : 'This exceeds the ceiling above and will be shortened at issuance.'}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Submit */}
            <div className="flex flex-wrap items-center gap-4">
                <button
                    onClick={handleSubmit}
                    disabled={!canSubmit}
                    className="px-6 py-2 text-sm font-semibold bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                    {loading ? 'Submitting...' : (tab === 'generate' ? 'Generate Key & Request Certificate' : 'Request Certificate')}
                </button>
                {hasValidationErrors && (
                    <span className="text-xs text-crit">Fix validation errors before submitting.</span>
                )}
                {!hasValidationErrors && selectedRequestProfile && missingProfiles.length > 0 && (
                    <FieldHint tone="warn">Choose {missingProfiles.join(' and ')} in step 1 before submitting.</FieldHint>
                )}
                {!hasValidationErrors && blockedUpnRows.length > 0 && (
                    <FieldHint tone="warn">Remove the UPN name, or paste or upload a CSR that carries it.</FieldHint>
                )}
            </div>

            {/* Result */}
            {error && (
                <div className="bg-crit-soft border border-crit/40 rounded-lg p-4">
                    <InlineNotice notice={error} variant="line" />
                </div>
            )}
            {success && (
                <div className={`${success.requiresApproval
                    ? 'bg-warn-soft border-warn/40'
                    : 'bg-ok-soft border-ok/40'} border rounded-lg p-4 space-y-3`}>
                    <p className={`text-sm font-semibold ${success.requiresApproval ? 'text-warn' : 'text-ok'}`}>
                        {success.message}
                    </p>
                    {success.requiresApproval && success.requiredApprovalCount != null && (
                        <DetailField label="Approvals Required" value={String(success.requiredApprovalCount)} />
                    )}
                    {success.requestId && <DetailField label="Request" value={success.requestId} mono />}
                    {success.keyHeld && success.requestId && (
                        <div className="bg-warn-soft border border-warn/40 rounded p-3 space-y-2">
                            {success.certificateIssued ? (
                                <HeldKeyDownload
                                    endpoint={endpoints.pkcs12(success.requestId)}
                                    requestId={success.requestId}
                                    fileName={success.subject || `request-${success.requestId}`}
                                    keyHeld
                                    issued
                                />
                            ) : (
                                <p className="text-xs text-warn">
                                    Your private key is held by the CA until the certificate is issued. Download the .pfx from{' '}
                                    <Link to={requestsPath} className="underline hover:text-warn">
                                        {mode === 'admin' ? 'the Requests page' : 'My Requests'}
                                    </Link>{' '}
                                    once it is approved.
                                </p>
                            )}
                            {success.csrPem && (
                                <div className="flex flex-wrap gap-2">
                                    <button type="button"
                                        onClick={() => downloadText(success.csrPem!, `request-${success.requestId || 'csr'}.csr`, 'application/pkcs10')}
                                        className="px-3 py-1.5 text-xs font-medium rounded border border-warn text-warn hover:bg-warn-soft transition-colors">
                                        Download CSR
                                    </button>
                                </div>
                            )}
                        </div>
                    )}
                    <div className="flex flex-wrap gap-3 pt-2">
                        <Link to={requestsPath} className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors">
                            {mode === 'admin' ? 'View Requests' : 'View My Requests'}
                        </Link>
                        <button onClick={dismissSuccess}
                            className="px-4 py-2 text-sm text-accent-ink border border-accent/40 rounded hover:bg-accent-soft transition-colors">
                            Submit Another
                        </button>
                    </div>
                </div>
            )}

        </div>
    );
};

export default CertificateRequestForm;
