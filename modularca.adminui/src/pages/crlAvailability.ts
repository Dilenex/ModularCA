/*
 * Which CRLs a CA publishes, read from its schedules, so the Distribution page links only to
 * downloads that exist. No React here, so tests/modularca.web.tests can cover it.
 */

/** A CRL schedule row as GET /api/v1/admin/crl-schedules returns it. */
export interface CrlScheduleRow {
    caCertificateId?: string;
    caId?: string;
    isDelta?: boolean;
    deltaInterval?: string | null;
}

/** A CA row as GET /api/v1/admin/authorities returns it. */
export interface CaRow {
    id?: string;
    caId?: string;
    certificateId?: string;
}

export interface CrlAvailability {
    full: boolean;
    delta: boolean;
}

/**
 * What the CA publishes. A delta CRL exists when the CA has a delta schedule, or a full schedule
 * that names a delta interval. A disabled schedule still counts: the last CRL it produced is
 * still served. With `schedules` null (not loaded, or the lookup failed) both are reported as
 * available, so a failed lookup hides no download.
 */
export const crlAvailability = (ca: CaRow, schedules: readonly CrlScheduleRow[] | null): CrlAvailability => {
    if (schedules === null) return { full: true, delta: true };
    const own = schedules.filter((s) => {
        const key = s.caCertificateId || s.caId;
        return !!key && (key === ca.certificateId || key === (ca.id || ca.caId));
    });
    return {
        full: own.some((s) => !s.isDelta),
        delta: own.some((s) => !!s.isDelta || !!s.deltaInterval?.trim()),
    };
};
