/**
 * Parsing for the error bodies this API returns, and the structured error the client throws.
 *
 * The API already produces well-shaped RFC 7807 responses. <c>RequestValidationMiddleware</c>
 * translates the RequestValidationException family into application/problem+json carrying
 * `detail`, plus `violations` for a certificate-policy failure and `parameter` / `supplied` /
 * `allowed` for a profile failure. The global handler in StartModularCA emits a sanitized 500
 * with a `correlationId`.
 *
 * None of that reached the operator. The client read the message as
 * `parsed.error || parsed.message || parsed.title`, and those problem bodies contain no `error`
 * and no `message` — so the chain landed on `title` and every other field was discarded. A
 * certificate-policy rejection that explains exactly which EKU was dropped and how to fix it
 * rendered in the toast as the four words "Certificate policy violation", and a 500 rendered as
 * "Internal Server Error" while the correlation id the handler had just generated was thrown
 * away.
 *
 * This module parses every shape the API actually emits into one structure:
 *   - problem+json from the two middlewares above
 *   - the legacy { error } / { message } bodies used by most controllers
 *   - ASP.NET model-state { title, errors: { field: [msg] } }
 *   - plain text, and an empty body
 *
 * `code` and `remediation` are read but not yet emitted by the server. They are part of the
 * planned error-code catalog; parsing them now means the server can start populating them
 * without a matching client change.
 */

/** One parsed error response, whatever shape the server sent it in. */
export interface ApiProblem {
    /** HTTP status, retained so callers can branch without re-reading the response. */
    status: number;
    /** Short classification, e.g. "Certificate policy violation". Always populated. */
    title: string;
    /** The explanatory sentence. This is the field worth showing a human. */
    detail?: string;
    /** Stable machine-readable error code. Not yet emitted by the server. */
    code?: string;
    /** What the operator should do about it. Not yet emitted by the server. */
    remediation?: string;
    /** Correlation id for the server log, from the body or the X-Correlation-Id header. */
    correlationId?: string;
    /** ProfileValidationException: the rejected parameter, e.g. "Signature algorithm". */
    parameter?: string;
    /** ProfileValidationException: the value the caller supplied. */
    supplied?: string;
    /** ProfileValidationException: the values the profile does permit. */
    allowed?: string[];
    /** ResourceNotFoundException: what kind of thing was missing, e.g. "Certificate authority". */
    resourceKind?: string;
    /** ResourceNotFoundException: the identifier the caller supplied, when it supplied one. */
    identifier?: string;
    /** CertificatePolicyViolationException: each rule that tripped, formatted "[Rule] message". */
    violations?: string[];
    /** ASP.NET model-state errors, keyed by field name. */
    fieldErrors?: Record<string, string[]>;
    /** Single-line rendering, used for the toast and for the thrown Error message. */
    message: string;
    /** The parsed JSON body, for callers that need a field this interface does not name. */
    raw?: unknown;
}

/**
 * Human-readable stand-in for a status code, used when the body carries no title.
 * Deliberately plainer than the RFC reason phrases — "Not permitted" reads better in a toast
 * than "Forbidden".
 */
const STATUS_TITLES: Record<number, string> = {
    400: 'Request rejected',
    401: 'Authentication required',
    403: 'Not permitted',
    404: 'Not found',
    405: 'Method not allowed',
    409: 'Conflict',
    413: 'Request too large',
    415: 'Unsupported media type',
    422: 'Request rejected',
    429: 'Too many requests',
    500: 'Server error',
    502: 'Upstream error',
    503: 'Service unavailable',
    504: 'Upstream timeout',
};

/** Returns a readable title for a status code. */
export function httpTitle(status: number): string {
    return STATUS_TITLES[status] ?? `HTTP ${status}`;
}

/** Narrows an unknown value to a non-empty string array, tolerating a single string. */
function asStringArray(value: unknown): string[] | undefined {
    if (Array.isArray(value)) {
        const items = value.filter((v): v is string => typeof v === 'string');
        return items.length > 0 ? items : undefined;
    }
    return typeof value === 'string' && value.length > 0 ? [value] : undefined;
}

/** Narrows an ASP.NET model-state errors object to field-keyed message lists. */
function asFieldErrors(value: unknown): Record<string, string[]> | undefined {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const out: Record<string, string[]> = {};
    for (const [field, messages] of Object.entries(value as Record<string, unknown>)) {
        const list = asStringArray(messages);
        if (list) out[field] = list;
    }
    return Object.keys(out).length > 0 ? out : undefined;
}

/** Narrows an unknown value to a non-blank string. */
function asText(value: unknown): string | undefined {
    return typeof value === 'string' && value.trim().length > 0 ? value : undefined;
}

/**
 * Builds the single-line rendering.
 *
 * `detail` wins over `title` because the title is a classification and the detail is the
 * explanation; falling back to the title is what produced the "Certificate policy violation"
 * toast this module exists to fix. The correlation id is appended only when it is worth
 * quoting — a 5xx, or a response with no explanation in it — so it does not add noise to a 400
 * that already says what went wrong.
 */
function composeMessage(p: Omit<ApiProblem, 'message'>): string {
    let message = p.detail && p.detail !== p.title ? p.detail : p.title;

    if (p.fieldErrors) {
        const flat = Object.entries(p.fieldErrors)
            .map(([field, messages]) => `${field}: ${messages.join(', ')}`)
            .join('; ');
        if (flat) message = message ? `${message} — ${flat}` : flat;
    }

    if (p.remediation) message = `${message} ${p.remediation}`;

    // Always appended, including for the unclassified -000 codes. A code that is present on
    // some refusals and missing on others cannot be relied on by whoever is reading a ticket,
    // and the judgement call about which failures "deserve" one is exactly what produces that
    // inconsistency. The bracketed suffix is short enough to survive in a toast.
    if (p.code) message = `${message} [${p.code}]`;

    if (p.correlationId && (p.status >= 500 || !p.detail)) {
        message = `${message} (correlation id ${p.correlationId})`;
    }

    return message;
}

/** Assembles the final problem, filling in the composed message. */
function finish(p: Omit<ApiProblem, 'message'>): ApiProblem {
    return { ...p, message: composeMessage(p) };
}

/**
 * Parses an error response body into an ApiProblem. Never throws: an unparseable body degrades
 * to the status line, because an error path that can itself fail is a worse bug than the error
 * it was reporting.
 *
 * @param status HTTP status of the response.
 * @param rawBody Body text, already read from the response.
 * @param headers Response headers, read for X-Correlation-Id when the body omits it.
 */
export function parseProblem(status: number, rawBody: string, headers?: Headers): ApiProblem {
    let correlationId: string | undefined;
    try {
        correlationId = headers?.get('X-Correlation-Id') ?? undefined;
    } catch {
        // Header access can throw on synthetic responses in tests; the id is optional.
    }

    const body = (rawBody ?? '').trim();
    if (!body) {
        return finish({ status, title: httpTitle(status), correlationId });
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        // Not JSON. Several endpoints answer errors in text/plain, and the whole body is then
        // the explanation.
        return finish({ status, title: httpTitle(status), detail: body, correlationId });
    }

    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return finish({ status, title: httpTitle(status), detail: body, correlationId });
    }

    const o = parsed as Record<string, unknown>;

    // Most controllers answer { error: "..." } (and a minority { message: "..." }) rather than
    // problem+json. Those strings are explanations, so they become the detail — not the title.
    const legacy = asText(o.error) ?? asText(o.message);

    return finish({
        status,
        title: asText(o.title) ?? httpTitle(status),
        detail: asText(o.detail) ?? legacy,
        code: asText(o.code),
        remediation: asText(o.remediation),
        correlationId: asText(o.correlationId) ?? correlationId,
        parameter: asText(o.parameter),
        supplied: asText(o.supplied),
        allowed: asStringArray(o.allowed),
        resourceKind: asText(o.resourceKind),
        identifier: asText(o.identifier),
        violations: asStringArray(o.violations),
        fieldErrors: asFieldErrors(o.errors),
        raw: parsed,
    });
}

/**
 * The error the API client throws. `message` stays a useful single line so the many callers
 * that catch and toast it keep working unchanged; `problem` carries the structure for callers
 * that want to render it properly.
 */
export class ApiError extends Error {
    /** The parsed response body. */
    readonly problem: ApiProblem;
    /** HTTP status, mirrored from the problem for convenience. */
    readonly status: number;
    /** Set when the server answered 403 with the step-up sentinel. */
    requiresStepUp?: boolean;

    /** Creates an error carrying a parsed problem response. */
    constructor(problem: ApiProblem) {
        super(problem.message);
        this.name = 'ApiError';
        this.problem = problem;
        this.status = problem.status;
        // Required for instanceof to hold when this is compiled down to ES5.
        Object.setPrototypeOf(this, ApiError.prototype);
    }
}

/** True when err is an ApiError, narrowing it for field access. */
export function isApiError(err: unknown): err is ApiError {
    return err instanceof ApiError;
}

/**
 * One advisory attached to an operation that *succeeded*.
 *
 * The mirror image of {@link ApiProblem}: same code, title, detail and remediation, because a
 * refusal and a silent adjustment are the same event to the person who asked for something and
 * did not get it. The difference is only whether a certificate came out the other end, which is
 * what `severity` records.
 */
export interface Diagnostic {
    /** 'info' | 'warning' | 'error' — see DiagnosticSeverity on the server. */
    severity: string;
    /** Stable identifier, e.g. MCA-ISS-003. */
    code: string;
    /** Short classification, e.g. "Extended key usage dropped". */
    title: string;
    /** The explanatory sentence. */
    detail: string;
    /** What to do about it, when the detail does not already say. */
    remediation?: string;
    /** The request or profile field this concerns, for inline rendering. */
    field?: string;
}

/**
 * Pulls diagnostics off a success response, tolerating the shapes that predate them.
 *
 * Issuance answered `{pem, warnings}` when a warning existed and a bare PEM string otherwise, so
 * a caller could not know what it was about to read. The server now always returns the envelope,
 * but this stays defensive: a string body, a missing array, or a legacy `warnings: string[]` all
 * degrade to something sensible rather than throwing inside a success handler.
 */
export function readDiagnostics(result: unknown): Diagnostic[] {
    if (!result || typeof result !== 'object') return [];
    const o = result as Record<string, unknown>;

    if (Array.isArray(o.diagnostics)) {
        return o.diagnostics.filter(
            (d): d is Diagnostic => !!d && typeof d === 'object' && typeof (d as Diagnostic).detail === 'string',
        );
    }

    // Pre-diagnostics responses carried only sentences. Surface them rather than dropping them.
    if (Array.isArray(o.warnings)) {
        return o.warnings
            .filter((w): w is string => typeof w === 'string')
            .map(detail => ({ severity: 'warning', code: '', title: 'Warning', detail }));
    }

    return [];
}

/**
 * Renders diagnostics as one line for a toast, with the code kept so it can be quoted later.
 * Returns an empty string when there is nothing to say, so callers can append unconditionally.
 */
export function describeDiagnostics(diagnostics: Diagnostic[]): string {
    if (diagnostics.length === 0) return '';
    return diagnostics
        .map(d => {
            const remediation = d.remediation ? ` ${d.remediation}` : '';
            const code = d.code ? ` [${d.code}]` : '';
            return `${d.detail}${remediation}${code}`;
        })
        .join(' ');
}
