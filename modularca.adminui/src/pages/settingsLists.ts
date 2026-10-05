import { listFromValue } from '@shared/components/chipList';

/*
 * Pure helpers for the list-valued fields on the Settings page. No React here, so they are
 * covered by tests/modularca.web.tests.
 */

/**
 * Signature algorithm names the issuance policy compares against (case-insensitive, whole name).
 *
 * CertPolicyService matches Forbidden Algorithms against the CSR's signature algorithm as
 * CertificateUtil names it: `SHA256withRSA`, `SHA1withRSA` and so on. An algorithm it has no name
 * for is reported by OID, so MD5withRSA can only be matched as 1.2.840.113549.1.1.4.
 */
export const POLICY_SIGNATURE_ALGORITHMS = [
    'SHA1withRSA', 'SHA1withDSA',
    'SHA256withRSA', 'SHA384withRSA', 'SHA512withRSA', 'SHA256withRSAandMGF1',
    'SHA256withECDSA', 'SHA384withECDSA', 'SHA512withECDSA',
    'Ed25519', 'Ed448', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
];

/**
 * Fragments the compliance scan looks for (case-insensitive, anywhere in the name) in an issued
 * certificate's signature algorithm as BouncyCastle names it, e.g. `SHA-1withRSA`, `MD5withRSA`.
 * The scan ignores hyphens on both sides, so `SHA1` and `SHA-1` both match.
 */
export const DEPRECATED_ALGORITHM_SUGGESTIONS = ['SHA1', 'MD5', 'MD2', 'SHA1withRSA', 'SHA1withECDSA', 'SHA1withDSA'];

/** The warning-day marks as chips, read from the property GET returns. */
export const warningDaysFromConfig = (section: unknown): string[] =>
    listFromValue((section as { warningDaysBeforeExpiry?: unknown } | null | undefined)?.warningDaysBeforeExpiry);

/** Mirrors CertExpiryNotificationUpdateRequest in AdminConfigController.cs. */
export interface CertExpiryNotificationBody {
    enabled: boolean;
    warningDays: number[];
    /** Sent empty: the schedule is edited on the job page, and the server ignores an empty one. */
    schedule: string;
}

/**
 * The PUT body for the expiry-notification card. GET returns the marks as
 * `warningDaysBeforeExpiry`, while PUT reads `WarningDays` as `List<int>`, so the chips are sent
 * as numbers under the PUT name.
 */
export const certExpiryNotificationBody = (section: { enabled?: boolean } | null | undefined, days: string[]): CertExpiryNotificationBody => ({
    enabled: !!section?.enabled,
    warningDays: days.map((d) => Number(d)),
    schedule: '',
});
