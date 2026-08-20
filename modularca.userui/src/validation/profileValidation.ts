/**
 * Client-side mirror of the server's `validate-against-profile` endpoint. Provides instant
 * feedback per keystroke without a network round-trip; the server endpoint remains canonical
 * and is still called on field-blur and at submit time. Keeping the two in sync is a
 * deliberate maintenance cost: when the C# validator changes, this module must change too.
 *
 * Regex semantics: profile rules use simple patterns (anchors, character classes, quantifiers)
 * that match identically between .NET and ECMAScript. Invalid regex values fail closed for DN
 * fields (mirrors server `ValidateFieldValue` behavior) and fail open for SANs (mirrors server
 * SAN-loop catch). Complex .NET-only constructs (named groups with .NET syntax, balancing
 * groups) would diverge — at which point either the server should be the only validator, or
 * the profile authoring UI should reject those patterns.
 *
 * Source of truth on the server side:
 *   ModularCA.API/Controllers/v1/User/UserCertSignRequestController.cs:255 (ValidateAgainstProfile)
 *   ModularCA.API/Controllers/v1/User/UserCertSignRequestController.cs:357 (ValidateFieldValue)
 *   plus the matching Admin* controller.
 */

export interface SubjectDnFieldRule {
    field: string;
    requirement: string; // "Required" | "Optional" | "Forbidden"
    fixedValue?: string | null;
    regex?: string | null;
    maxLength?: number | null;
    defaultValue?: string | null;
}

export interface SanTypeRule {
    regex?: string | null;
    maxCount: number;
}

export interface SanRules {
    allowedTypes: string[];
    required: boolean;
    rules: Record<string, SanTypeRule>;
}

export interface SanEntry { type: string; value: string; }

export interface FieldValidationResult {
    field: string;
    status: 'valid' | 'warning' | 'error';
    message: string | null;
}

export interface SanValidationResult {
    type: string;
    value: string;
    status: 'valid' | 'warning' | 'error';
    message: string | null;
}

export interface ValidationResult {
    valid: boolean;
    fieldResults: FieldValidationResult[];
    sanResults: SanValidationResult[];
}

/**
 * Runs the same checks the server runs. Pure function — no I/O, no async, no timing.
 * Safe to call on every keystroke.
 */
export function validateAgainstProfileClient(
    subject: Record<string, string>,
    sans: SanEntry[],
    dnRules: SubjectDnFieldRule[],
    sanRules: SanRules,
): ValidationResult {
    const result: ValidationResult = { valid: true, fieldResults: [], sanResults: [] };

    // Per-rule pass — handles Required/Optional/Forbidden semantics + regex/length/fixed checks.
    for (const rule of dnRules) {
        const value = subject[rule.field] || '';
        const hasValue = value.trim().length > 0;
        let r: FieldValidationResult = { field: rule.field, status: 'valid', message: null };

        if (rule.requirement === 'Forbidden') {
            if (hasValue) {
                r = { field: rule.field, status: 'error', message: 'This field is not allowed by the profile.' };
                result.valid = false;
            } else {
                r = { field: rule.field, status: 'valid', message: 'Forbidden (correctly absent).' };
            }
        } else if (rule.requirement === 'Required') {
            if (!hasValue) {
                r = { field: rule.field, status: 'error', message: 'This field is required.' };
                result.valid = false;
            } else {
                r = validateFieldValue(rule, value);
                if (r.status === 'error') result.valid = false;
            }
        } else {
            // Optional (or any other unrecognized requirement) — empty is a warning, populated runs the value checks.
            if (!hasValue) {
                r = { field: rule.field, status: 'warning', message: 'Optional field, not provided.' };
            } else {
                r = validateFieldValue(rule, value);
                if (r.status === 'error') result.valid = false;
            }
        }
        result.fieldResults.push(r);
    }

    // Extra subject keys not covered by any rule — surfaced as a warning so operators know
    // they typed something the profile won't carry into the issued cert.
    for (const [key, val] of Object.entries(subject)) {
        if (val.trim().length > 0 && !dnRules.some(r => r.field === key)) {
            result.fieldResults.push({
                field: key,
                status: 'warning',
                message: 'No rule defined for this field in the profile.',
            });
        }
    }

    // SAN per-entry pass + per-type count tracking.
    const sanCountsByType = new Map<string, number>();
    const allowedTypesLower = (sanRules.allowedTypes || []).map(t => t.toLowerCase());

    for (const san of sans) {
        const sanResult: SanValidationResult = { type: san.type, value: san.value, status: 'valid', message: null };
        if (!allowedTypesLower.includes(san.type.toLowerCase())) {
            sanResult.status = 'error';
            sanResult.message = `SAN type '${san.type}' is not allowed.`;
            result.valid = false;
        } else {
            const typeRule = sanRules.rules?.[san.type];
            if (typeRule?.regex && typeRule.regex.trim().length > 0) {
                try {
                    const re = new RegExp(typeRule.regex);
                    if (!re.test(san.value)) {
                        sanResult.status = 'error';
                        sanResult.message = `Does not match pattern: ${typeRule.regex}`;
                        result.valid = false;
                    }
                } catch {
                    // Mirror server: an un-evaluable profile pattern is an error against the
                    // profile, not a pass. (The server also time-boxes the match; the browser
                    // cannot, so a pathological pattern only costs the user's own tab.)
                    sanResult.status = 'error';
                    sanResult.message = `The profile's pattern for SAN type '${san.type}' could not be evaluated; this value could not be validated. Ask an administrator to review the profile.`;
                    result.valid = false;
                }
            }
        }

        // Mirror server SanShapeValidator — runs only if no upstream error so users
        // see one reason at a time instead of a confusing pile.
        if (sanResult.status !== 'error') {
            const shapeError = validateSanShape(san.type, san.value);
            if (shapeError) {
                sanResult.status = 'error';
                sanResult.message = shapeError;
                result.valid = false;
            }
        }

        sanCountsByType.set(san.type, (sanCountsByType.get(san.type) || 0) + 1);
        result.sanResults.push(sanResult);
    }

    // Per-type max-count enforcement: mark trailing entries as error (matches server's Reverse().Take()).
    for (const [type, count] of sanCountsByType.entries()) {
        const typeRule = sanRules.rules?.[type];
        if (typeRule && count > typeRule.maxCount) {
            const overflow = count - typeRule.maxCount;
            const trailing = result.sanResults
                .map((s, idx) => ({ s, idx }))
                .filter(x => x.s.type === type)
                .reverse()
                .slice(0, overflow);
            for (const { s } of trailing) {
                s.status = 'error';
                s.message = `Exceeds max count of ${typeRule.maxCount} for ${type}.`;
                result.valid = false;
            }
        }
    }

    if (sanRules.required && sans.length === 0) {
        result.sanResults.push({ type: '', value: '', status: 'error', message: 'At least one SAN is required.' });
        result.valid = false;
    }

    return result;
}

/**
 * Mirrors `ModularCA.Shared.Utils.SanShapeValidator.ValidateShape`. Returns null if the
 * value's shape matches the SAN type or the type isn't shape-checked, otherwise an
 * error message. Catches IP/DNS swaps before the server's BouncyCastle GeneralName
 * ctor would throw at issuance time.
 */
export function validateSanShape(type: string, value: string): string | null {
    if (!type) return null;
    switch (type.trim().toUpperCase()) {
        case 'IP':
            return isValidIp(value) ? null : `'${value}' is not a valid IPv4 or IPv6 address.`;
        case 'DNS':
            return isValidFqdn(value) ? null : `'${value}' is not a valid DNS hostname (FQDN).`;
        default:
            return null;
    }
}

function isValidIpv4(s: string): boolean {
    const parts = s.split('.');
    if (parts.length !== 4) return false;
    for (const part of parts) {
        if (!/^\d+$/.test(part)) return false;
        if (part.length > 1 && part.startsWith('0')) return false;
        const n = Number(part);
        if (n < 0 || n > 255) return false;
    }
    return true;
}

function isValidIpv6(s: string): boolean {
    if (s.includes('%')) return false;
    if (s.length === 0 || s.length > 45) return false;
    const doubleColon = s.split('::').length - 1;
    if (doubleColon > 1) return false;
    const groups = doubleColon === 1 ? s.split('::') : [s];
    const groupRe = /^[0-9a-fA-F]{1,4}$/;
    let total = 0;
    for (const half of groups) {
        if (half === '') continue;
        const parts = half.split(':');
        for (const p of parts) {
            if (p.includes('.')) {
                if (!isValidIpv4(p)) return false;
                total += 2;
                continue;
            }
            if (!groupRe.test(p)) return false;
            total += 1;
        }
    }
    return doubleColon === 1 ? total <= 7 : total === 8;
}

function isValidIp(s: string): boolean {
    if (!s) return false;
    return isValidIpv4(s) || isValidIpv6(s);
}

function isValidFqdn(s: string): boolean {
    if (!s) return false;
    // Reject IP-shaped strings — those belong in IP SANs.
    if (isValidIp(s)) return false;
    let v = s.endsWith('.') ? s.slice(0, -1) : s;
    if (v.length === 0 || v.length > 253) return false;
    let labels = v.split('.');
    if (labels[0] === '*') {
        if (labels.length < 2) return false;
        labels = labels.slice(1);
    }
    const labelRe = /^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$/;
    for (const label of labels) {
        if (!labelRe.test(label)) return false;
    }
    return true;
}

/**
 * Mirrors `ValidateFieldValue` on the server: maxLength → regex → fixedValue, in that order.
 * Returns the first error encountered.
 */
function validateFieldValue(rule: SubjectDnFieldRule, value: string): FieldValidationResult {
    if (rule.maxLength != null && value.length > rule.maxLength) {
        return { field: rule.field, status: 'error', message: `Exceeds max length of ${rule.maxLength}.` };
    }
    if (rule.regex && rule.regex.trim().length > 0) {
        try {
            const re = new RegExp(rule.regex);
            if (!re.test(value)) {
                return { field: rule.field, status: 'error', message: `Does not match pattern: ${rule.regex}` };
            }
        } catch {
            // Mirror server: fail closed on invalid DN-field regex.
            return {
                field: rule.field,
                status: 'error',
                message: `Profile regex is invalid for field '${rule.field}'; value cannot be validated.`,
            };
        }
    }
    if (rule.fixedValue && rule.fixedValue.trim().length > 0 && value !== rule.fixedValue) {
        return { field: rule.field, status: 'error', message: `Must be '${rule.fixedValue}' (fixed by profile).` };
    }
    return { field: rule.field, status: 'valid', message: null };
}
