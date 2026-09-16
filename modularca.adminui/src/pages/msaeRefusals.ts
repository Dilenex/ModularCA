/**
 * Plain-language explanations for the failures the MSAE (Windows autoenrollment) audit records.
 *
 * The audit row carries what the server knew at the moment it refused: a refusal name such as
 * `Kerberos token refused: Invalid`, or one sentence from the enrollment service. Neither says
 * what an operator should do next, and the lab spent hours on each of them the first time. This
 * module maps every pattern the server writes to a title, an explanation of what the client and
 * the server disagreed about, and the change that resolves it, so the audit page can say it where
 * the row lands instead of sending the operator to the source.
 *
 * Kept free of React so the audit table, the row drawer and the detail page share one matcher.
 */

/** The fields of an MSAE audit row this module reads. Every one is optional: older rows lack the newer columns. */
export interface MsaeAuditRow {
    success?: boolean;
    operation?: string | null;
    errorMessage?: string | null;
    realm?: string | null;
    authMethod?: string | null;
    callerPrincipal?: string | null;
    templateName?: string | null;
    caLabel?: string | null;
    tenantId?: string | null;
    certificateAuthorityId?: string | null;
    caId?: string | null;
}

export interface MsaeFailureExplanation {
    /** Short classification, fit for a table cell. */
    title: string;
    /** What the client and the server disagreed about. */
    explanation: string;
    /** The change that resolves it. */
    fix: string;
    /** Where the fix is made, when the console has a page for it. */
    link?: { label: string; path: string };
}

/** The realm page of the tenant the CA belongs to, where realm bindings and their keys live. */
function realmLink(row: MsaeAuditRow): MsaeFailureExplanation['link'] | undefined {
    return row.tenantId ? { label: 'Open realm bindings', path: `/tenants/${row.tenantId}?tab=kerberos` } : undefined;
}

/**
 * The console scope is keyed by CA label (`?ca=<label>`, see scope.ts), and the audit row carries
 * the label on every entry, so the link scopes by label. A CA id would not resolve.
 */
function caScoped(path: string, row: MsaeAuditRow): string {
    return row.caLabel ? `${path}?ca=${encodeURIComponent(row.caLabel)}` : path;
}

function templatesLink(row: MsaeAuditRow): MsaeFailureExplanation['link'] {
    return { label: 'Open templates', path: caScoped('/templates', row) };
}

function protocolsLink(row: MsaeAuditRow): MsaeFailureExplanation['link'] {
    return { label: 'Open protocol settings', path: caScoped('/authorities/protocols', row) };
}

/**
 * Reads the key versions out of an `Invalid` refusal detail, which the acceptor writes as
 * `ticket kvno 7 aes256-cts-hmac-sha1-96; kvno 5 Aes256: ...: ... | kvno 6 Aes256: ...`. Returns
 * the ticket's version and the versions the server tried, or nulls when the detail is absent.
 */
function parseKvno(detail: string): { ticket: number | null; tried: number[] } {
    const ticketMatch = /ticket kvno (\d+)/i.exec(detail);
    const ticket = ticketMatch ? parseInt(ticketMatch[1], 10) : null;
    const tried: number[] = [];
    const re = /(?:^|[;|]\s*)kvno (\d+)/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(detail)) !== null) tried.push(parseInt(m[1], 10));
    return { ticket, tried };
}

function explainKerberos(refusal: string, detail: string, row: MsaeAuditRow): MsaeFailureExplanation | null {
    const realm = row.realm ? `realm ${row.realm}` : 'its realm';
    switch (refusal) {
        case 'WrongTenant':
            return {
                title: 'Ticket from another tenant’s forest',
                explanation: `The ticket is valid, but ${realm} is bound to a different tenant than the one that owns CA ${row.caLabel || 'this CA'}. A binding grants a forest access to one tenant’s CAs only.`,
                fix: 'Point the client at a CA in the tenant its forest is bound to, or bind the forest’s realm on this tenant as well.',
                link: realmLink(row),
            };
        case 'UnknownRealm':
            return {
                title: 'Realm not bound',
                explanation: `The ticket names ${realm}, and no enabled binding on this tenant carries that realm: either the realm was never bound or its binding is disabled.`,
                fix: 'Bind the realm on the tenant that owns the CA, or enable the existing binding, and import the service account’s key.',
                link: realmLink(row),
            };
        case 'Invalid': {
            const { ticket, tried } = parseKvno(detail);
            const newest = tried.length ? Math.max(...tried) : null;
            const stale = ticket != null && newest != null && ticket > newest;
            const versions = ticket != null
                ? ` The ticket was encrypted with key version ${ticket}; the server tried ${tried.length ? `version${tried.length === 1 ? '' : 's'} ${tried.join(', ')}` : 'every stored version'}.`
                : '';
            return {
                title: stale ? 'Service account password changed' : 'No stored key decrypts the ticket',
                explanation: `The ticket is for ${realm} and the realm is bound, but none of the keys stored for it decrypted the ticket. That is almost always a wrong or rotated service account password.${versions}`,
                fix: stale
                    ? `The ticket’s key version (${ticket}) is newer than every stored version, so the account’s password changed after the key was imported. Import a key for the new password (version ${ticket}) on the realm binding.`
                    : 'Re-import the service account key from the current password or a fresh keytab, and confirm the account name and realm match the binding.',
                link: realmLink(row),
            };
        }
        case 'NtlmOffered':
            return {
                title: 'Client fell back to NTLM',
                explanation: 'The client sent an NTLM token instead of a Kerberos ticket, which means it could not obtain a ticket for the name it computed for the CA host. Windows canonicalises the host name before asking its KDC, so a hosts-file alias or a CNAME turns the request into one for a name that has no SPN.',
                fix: 'Reach the CA by the host name that carries the SPN (an A record, not a CNAME or hosts-file alias), and register that SPN on the service account. NTLM is never accepted.',
                link: realmLink(row),
            };
        case 'Malformed':
            if (/NTLMSSP/i.test(detail)) return explainKerberos('NtlmOffered', detail, row);
            return {
                title: 'Token was not SPNEGO',
                explanation: `The Authorization header did not carry a parseable SPNEGO token${detail ? ` (${detail})` : ''}. A proxy that rewrites headers, or a client that is not Windows autoenrollment, can produce this.`,
                fix: 'Confirm the client reaches the CA directly over HTTPS and that nothing between them alters the Authorization header.',
                link: realmLink(row),
            };
        case 'WrongServicePrincipal':
            return {
                title: 'Ticket for a different SPN',
                explanation: `The ticket was issued for a service principal other than the one the binding for ${realm} expects. The client asked its KDC for a name that does not match the binding, usually because the CA is reached by a different host name than the one the binding names.`,
                fix: 'Make the binding’s service principal match the host name clients use, or point clients at the host name the binding names.',
                link: realmLink(row),
            };
        case 'PrincipalKindNotAllowed':
            return {
                title: 'Principal kind not allowed',
                explanation: `The ticket authenticated, but the binding for ${realm} does not allow this kind of principal: machine accounts or user accounts are switched off on it.`,
                fix: 'Allow the principal kind on the binding (machines for computer templates, users for user templates), or stop targeting that kind with autoenrollment policy.',
                link: realmLink(row),
            };
        case 'ForeignClientRealm':
            return {
                title: 'Cross-realm ticket',
                explanation: `The client belongs to a realm other than ${realm}, the one that issued the ticket. Cross-realm (trust-referred) tickets are not supported.`,
                fix: 'Bind the client’s own realm on the tenant and let it authenticate against that binding directly.',
                link: realmLink(row),
            };
        default:
            return {
                title: `Kerberos refusal: ${refusal}`,
                explanation: `The Kerberos ticket was refused with reason ${refusal}${detail ? ` (${detail})` : ''}.`,
                fix: 'Check the realm binding for the ticket’s realm and the server log for the full detail.',
                link: realmLink(row),
            };
    }
}

/**
 * Explains a failed MSAE audit row, or returns null when the row succeeded or its message matches
 * nothing this module knows. The message patterns follow what MsaeController and
 * MsaeEnrollmentService write; when a detail is appended after a Kerberos refusal name it is read
 * for the key versions.
 */
export function explainMsaeFailure(row: MsaeAuditRow | null | undefined): MsaeFailureExplanation | null {
    if (!row) return null;
    const message = (row.errorMessage || '').trim();
    if (!message) return null;

    const krb = /^Kerberos token refused:\s*([A-Za-z]+)\s*[:;,(-]?\s*(.*)$/s.exec(message);
    if (krb) return explainKerberos(krb[1], (krb[2] || '').replace(/\)$/, '').trim(), row);

    if (/^No credential presented/i.test(message)) {
        return {
            title: 'Challenged, no credential yet',
            explanation: 'The client sent no Authorization header and received the 401 Negotiate challenge. One of these per exchange is normal: the client answers the challenge with a ticket and the next row is the accepted request. If no accepted row follows from the same address, the client never answered, which points at an auto-logon policy that will not send credentials to this host, or at a client that fell back to NTLM and gave up.',
            fix: 'Look for the row that follows. If there is none, put the CA host in the client’s intranet zone (or the autoenrollment policy’s automatic-logon sites) and confirm the client can get a Kerberos ticket for the host name it uses.',
            link: protocolsLink(row),
        };
    }

    if (/^Kerberos authentication is not enabled/i.test(message)) {
        return {
            title: 'Kerberos not enabled on this CA',
            explanation: `The client presented a Kerberos ticket, but the MSAE authentication mode on CA ${row.caLabel || 'this CA'} does not accept Kerberos.`,
            fix: 'Enable Kerberos in the CA’s MSAE protocol settings, or reconfigure the client for the mode the CA accepts.',
            link: protocolsLink(row),
        };
    }

    if (/requires approval/i.test(message)) {
        return {
            title: 'Template requires approval',
            explanation: 'The template’s request profile requires approval, and this build refused the enrollment outright instead of parking it. Newer builds accept the request as pending and let the client poll until it is issued.',
            fix: 'Approve requests for this template from the approval queue, or attach a request profile that does not require approval if Windows clients should be issued at once.',
            link: templatesLink(row),
        };
    }

    const oid = /^Certificate template (?:OID )?'([^']+)' is not available\.?$/i.exec(message);
    if (oid) {
        const named = /OID/i.test(message) ? `OID ${oid[1]}` : `'${oid[1]}'`;
        return {
            title: 'Template not offered',
            explanation: `The client asked for template ${named}, and no enabled template offered to Windows on CA ${row.caLabel || 'this CA'} carries it. Either the client’s cached policy is stale (Windows caches the policy list for eight hours) or the template was unoffered, disabled or deleted after the client fetched its policy.`,
            fix: 'If the template should be offered, offer it (or re-enable it) on the CA. If the client should stop asking for it, clear the client’s policy cache or re-register the policy server so it fetches a fresh list.',
            link: templatesLink(row),
        };
    }

    if (/^The certificate to renew/i.test(message)) {
        const expired = /has expired/i.test(message);
        const revoked = /is revoked/i.test(message);
        const foreign = /was not issued by/i.test(message);
        return {
            title: expired ? 'Renewing an expired certificate' : revoked ? 'Renewing a revoked certificate' : foreign ? 'Renewing a certificate from elsewhere' : 'Renewal refused',
            explanation: expired
                ? 'The client tried to renew a certificate that has already expired. Renewal proves possession of the old certificate, and an expired one no longer counts.'
                : revoked
                    ? 'The client tried to renew a certificate that this CA revoked. A revoked certificate cannot vouch for its successor.'
                    : foreign
                        ? `The client tried to renew a certificate that ${/by CA/i.test(message) ? 'a different CA issued' : 'this service did not issue'}, so the CA has nothing to renew it against.`
                        : message,
            fix: 'The client should enroll afresh rather than renew: remove the old certificate from its store (or let autoenrollment replace it) and request a new one.',
            link: templatesLink(row),
        };
    }

    if (/^The renewal request is not signed by the certificate it names/i.test(message)) {
        return {
            title: 'Renewal not signed by the old certificate',
            explanation: 'The request names a certificate to renew but is not signed by that certificate’s key, so the CA cannot tell that the requester holds it. The client probably lost or replaced the private key.',
            fix: 'The client should enroll afresh with a new key instead of renewing.',
            link: templatesLink(row),
        };
    }

    if (/^Request .* was not submitted by this caller/i.test(message)) {
        return {
            title: 'Pending request asked for by another identity',
            explanation: `A pending request was submitted by one caller and this poll for it came from another${row.callerPrincipal ? ` (${row.callerPrincipal})` : ''}. A pending request is released only to the identity that submitted it.`,
            fix: 'Poll from the account that submitted the request. If the machine was reimaged or renamed, let it enroll afresh; the old pending request can be rejected from the approval queue.',
        };
    }

    return null;
}
