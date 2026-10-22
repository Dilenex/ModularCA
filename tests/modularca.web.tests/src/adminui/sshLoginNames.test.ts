import { describe, expect, it } from 'vitest';
import {
    BEFORE_LOGIN_NAMES, NOT_RECORDED, canOnSshCa, certProfileChoices, certificateBadge, certificateStatus, chosenCombination, dateFieldValue,
    defaultHostKeyFile, defaultKeyFile, defaultValidity, endOfDayIso, existingGrants, findQuery, grantEnd, grantEndToSend, grantTermProblems, grantTermsBody,
    groundText, groundWords, heldSourceText, issuedByDetail, issuedByText, issuedToDetail, issuedToText, jsonList, logLineProblem, loginNameError,
    longestCertificateText, parseSshdLogLine, removeGrantQuestion, requestProfileChoices, revokeAllSentence, revokedSentence, serviceKeyId,
    serviceLabelError, signingProfileChoices, sshdKeyType, validityLimit, validityLimitText, validityProblem,
    type SshCertificateView, type SshLoginNameGrant, type SshRequestProfileCombination,
} from '@adminui/pages/sshLoginNames';
import type { EffectiveCapabilities } from '@adminui/authz';

/**
 * How the console reads SSH login names. The rule is ModularCA.Shared/Utils/SshLoginNameRules.cs,
 * the key id rule ModularCA.Core/Services/SshKeyIds.cs, the validity rule
 * SshLoginNameHolding.ValidBefore, and the answers those of AdminSshLoginNameController and
 * UserSshController.
 */

const NOW = new Date('2026-10-07T10:00:00Z');
const day = (iso: string) => iso.slice(0, 10);

describe('the login name rule, as typed', () => {
    it('accepts what SshLoginNameRules accepts', () => {
        for (const name of ['root', 'deploy', '_svc', '0day', 'web.ops', 'a_b', 'alice@example.com', 'c++', 'a-b', 'A', 'x'.repeat(128)]) {
            expect(loginNameError(name), name).toBeNull();
        }
    });

    it('refuses an empty name, a bad first character, a bad later character and a name that is too long', () => {
        for (const name of ['', '-rf', '.hidden', '@home', '+x', 'two words', 'tab\tname', 'sl/ash', 'comma,name', 'col:on', 'déploy', 'x'.repeat(129)]) {
            expect(loginNameError(name), JSON.stringify(name)).not.toBeNull();
        }
    });

    it('names a short entry in its message and not a long one', () => {
        expect(loginNameError('two words')).toContain('"two words" is not a login name');
        expect(loginNameError('x'.repeat(129))).toMatch(/^This entry is not a login name/);
    });

    it('keeps upper and lower case apart', () => {
        const grants = [grant({ id: 'g1', loginName: 'Deploy', user: { id: 'u1', username: 'alice' } })];
        expect(existingGrants(grants, ['deploy'], { userId: 'u1' })).toEqual([]);
        expect(existingGrants(grants, ['Deploy'], { userId: 'u1' })).toHaveLength(1);
    });
});

describe('a service identity', () => {
    it('takes a label of 1 to 64 letters, digits and . _ -', () => {
        expect(serviceLabelError('backup-runner')).toBeNull();
        expect(serviceLabelError('a.b_c-1')).toBeNull();
        expect(serviceLabelError('x'.repeat(64))).toBeNull();
        for (const label of ['', 'two words', 'svc:x', 'a@b', 'x'.repeat(65)]) expect(serviceLabelError(label), label).not.toBeNull();
    });

    it('is logged as svc: and its label', () => {
        expect(serviceKeyId('backup-runner')).toBe('svc:backup-runner');
    });
});

describe('lists the API keeps as text', () => {
    it('reads a JSON array inside a string, a real array, and nothing', () => {
        expect(jsonList('["alice","root"]')).toEqual(['alice', 'root']);
        expect(jsonList(['a', 'b'])).toEqual(['a', 'b']);
        expect(jsonList('[]')).toEqual([]);
        expect(jsonList(null)).toEqual([]);
        expect(jsonList(undefined)).toEqual([]);
        expect(jsonList('')).toEqual([]);
    });

    it('falls back to commas for text that is not JSON', () => {
        expect(jsonList('alice, root')).toEqual(['alice', 'root']);
    });
});

function grant(over: Partial<SshLoginNameGrant>): SshLoginNameGrant {
    return {
        id: 'g', sshCaKey: { id: 'k1', name: 'prod-user-ca' }, loginName: 'deploy', user: null, group: null, maxValidityHours: null, expiresAt: null,
        ended: false, note: null, grantedBy: { id: 'a1', username: 'edward' }, grantedAt: '2026-10-01T00:00:00Z', liveCertificates: 0, ...over,
    };
}

describe('when a grant ends', () => {
    it('has no badge with no end, or with an end more than two weeks away', () => {
        expect(grantEnd(null, NOW)).toEqual({ state: 'never', daysLeft: null, badge: null });
        expect(grantEnd('2026-10-22T10:00:01Z', NOW)).toMatchObject({ state: 'later', badge: null });
    });

    it('is marked within fourteen days, with the days left', () => {
        expect(grantEnd('2026-10-14T10:00:00Z', NOW)).toEqual({ state: 'soon', daysLeft: 7, badge: { status: 'expired', label: '7 d' } });
        expect(grantEnd('2026-10-21T10:00:00Z', NOW)).toMatchObject({ state: 'soon', daysLeft: 14 });
        expect(grantEnd('2026-10-07T18:00:00Z', NOW).badge).toEqual({ status: 'expired', label: 'Under 1 d' });
    });

    it('reads Ended once past, or when the API says so', () => {
        expect(grantEnd('2026-10-07T10:00:00Z', NOW).badge).toEqual({ status: 'disabled', label: 'Ended' });
        expect(grantEnd('2026-10-01T00:00:00Z', NOW).state).toBe('ended');
        expect(grantEnd('2026-10-07T10:00:05Z', NOW, true).state).toBe('ended');
    });
});

describe('the end of a grant, as a date field', () => {
    it('is the end of that day in the reader\'s time zone', () => {
        const iso = endOfDayIso('2026-10-14')!;
        const end = new Date(iso);
        expect([end.getFullYear(), end.getMonth() + 1, end.getDate(), end.getHours(), end.getMinutes(), end.getSeconds()]).toEqual([2026, 10, 14, 23, 59, 59]);
        expect(dateFieldValue(iso)).toBe('2026-10-14');
    });

    it('is nothing for an empty or unreadable field', () => {
        expect(endOfDayIso('')).toBeNull();
        expect(endOfDayIso('14/10/2026')).toBeNull();
        expect(grantEndToSend('')).toBeNull();
        expect(dateFieldValue(null)).toBe('');
    });

    it('keeps the stored moment while the day is unchanged, so saving does not move the end', () => {
        const stored = new Date(2026, 9, 14, 9, 30, 0).toISOString();
        expect(grantEndToSend('2026-10-14', stored)).toBe(stored);
        expect(grantEndToSend('2026-10-15', stored)).toBe(endOfDayIso('2026-10-15'));
    });
});

describe('the limit, end and note of a grant', () => {
    const terms = (over: Partial<{ hours: string; endDate: string; note: string }>) => ({ hours: '', endDate: '', note: '', ...over });

    it('accepts empty terms, and a limit from 1 to the key\'s maximum', () => {
        expect(grantTermProblems(terms({}), 720, NOW)).toEqual([]);
        expect(grantTermProblems(terms({ hours: '1' }), 720, NOW)).toEqual([]);
        expect(grantTermProblems(terms({ hours: '720' }), 720, NOW)).toEqual([]);
    });

    it('refuses a limit of 0 or over the key\'s maximum, naming the maximum', () => {
        expect(grantTermProblems(terms({ hours: '0' }), 720, NOW)[0]).toContain('between 1 and 720 hours');
        expect(grantTermProblems(terms({ hours: '721' }), 720, NOW)).toHaveLength(1);
    });

    it('refuses an end in the past, but not the unchanged end of a grant that has already ended', () => {
        expect(grantTermProblems(terms({ endDate: '2026-10-01' }), 720, NOW)).toEqual(['The end is in the past. Remove the grant to end it now.']);
        const stored = new Date(2026, 9, 1, 12, 0, 0).toISOString();
        expect(grantTermProblems(terms({ endDate: '2026-10-01' }), 720, NOW, stored)).toEqual([]);
        expect(grantTermProblems(terms({ endDate: '2026-12-01' }), 720, NOW)).toEqual([]);
    });

    it('refuses a note over 256 characters', () => {
        expect(grantTermProblems(terms({ note: 'x'.repeat(256) }), 720, NOW)).toEqual([]);
        expect(grantTermProblems(terms({ note: 'x'.repeat(257) }), 720, NOW)).toHaveLength(1);
    });

    it('sends null for what is left empty, so a change clears it', () => {
        expect(grantTermsBody(terms({}))).toEqual({ maxValidityHours: null, expiresAt: null, note: null });
        expect(grantTermsBody(terms({ hours: '8', note: '  break-glass  ', endDate: '2026-10-14' })))
            .toEqual({ maxValidityHours: 8, expiresAt: endOfDayIso('2026-10-14'), note: 'break-glass' });
    });
});

describe('a name the target already has', () => {
    const grants = [
        grant({ id: 'g1', loginName: 'deploy', group: { id: 'grp1', name: 'web-ops', displayName: 'Web operators', memberCount: 4 } }),
        grant({ id: 'g2', loginName: 'root', user: { id: 'u1', username: 'alice' }, ended: true, expiresAt: '2026-10-01T00:00:00Z' }),
        grant({ id: 'g3', loginName: 'root', user: { id: 'u2', username: 'bob' } }),
    ];

    it('is found for the same user or the same group only', () => {
        expect(existingGrants(grants, ['root', 'backup'], { userId: 'u1' }).map((g) => g.id)).toEqual(['g2']);
        expect(existingGrants(grants, ['deploy'], { groupId: 'grp1' }).map((g) => g.id)).toEqual(['g1']);
        expect(existingGrants(grants, ['deploy'], { userId: 'u1' })).toEqual([]);
        expect(existingGrants(grants, ['root'], { groupId: 'grp1' })).toEqual([]);
    });

    it('includes a grant that has ended, since it still holds its place', () => {
        expect(existingGrants(grants, ['root'], { userId: 'u1' })[0].ended).toBe(true);
    });

    it('is nothing while no target is chosen', () => {
        expect(existingGrants(grants, ['root'], { userId: null })).toEqual([]);
        expect(existingGrants(grants, ['root'], {})).toEqual([]);
    });
});

describe('wording', () => {
    it('says the longest certificate, or the CA maximum', () => {
        expect(longestCertificateText(24)).toBe('24 h');
        expect(longestCertificateText(null)).toBe('CA maximum');
        expect(longestCertificateText(undefined, 720)).toBe('CA maximum, 720 h');
    });

    it('says where a held name comes from, to its holder and about someone else', () => {
        expect(heldSourceText({ source: 'own' }, 'you')).toBe('Your username');
        expect(heldSourceText({ source: 'own' }, 'bob')).toBe('Own username');
        expect(heldSourceText({ source: 'group', groupName: 'Web operators' }, 'you')).toBe('Through the group Web operators');
        expect(heldSourceText({ source: 'user', expiresAt: '2026-10-14T21:59:59Z' }, 'you', day)).toBe('Granted to you until 2026-10-14');
        expect(heldSourceText({ source: 'user' }, 'bob')).toBe('Granted to bob');
    });

    it('says why a certificate\'s holder had a login name', () => {
        expect(groundText({ name: 'alice', source: 'own' }, 'alice')).toBe('Own username');
        expect(groundText({ name: 'deploy', source: 'group', groupId: 'grp1', groupName: 'Web operators' }, 'alice')).toBe('Through the group Web operators');
        expect(groundText({ name: 'root', source: 'user', grantedByUsername: 'edward', expiresAt: '2026-10-14T21:59:59Z' }, 'alice', day))
            .toBe('Granted to alice by edward, until 2026-10-14');
        expect(groundText({ name: 'backup', source: 'typed' }, 'svc:backup')).toBe('Typed by whoever signed it, for a service identity');
    });

    it('keeps the group apart, so a page can link it', () => {
        expect(groundWords({ name: 'deploy', source: 'group', groupName: 'Web operators', grantedByUsername: 'edward' }, 'alice'))
            .toEqual({ lead: 'Through the group ', groupName: 'Web operators', tail: ', granted by edward' });
        expect(groundWords({ name: 'deploy', source: 'group' }, 'alice').groupName).toBeNull();
    });

    it('counts what a change revoked', () => {
        expect(revokedSentence(0)).toBe('No certificate was revoked.');
        expect(revokedSentence(1)).toBe('1 certificate was revoked.');
        expect(revokedSentence(3)).toBe('3 certificates were revoked.');
    });

    it('says how many live certificates removing a grant touches', () => {
        const g = grant({ loginName: 'deploy', group: { id: 'grp1', name: 'web-ops', displayName: 'Web operators', memberCount: 4 } });
        expect(removeGrantQuestion({ ...g, liveCertificates: 0 }))
            .toBe('Remove the grant of "deploy" to Web operators on prod-user-ca? No live certificate carries the name under this grant.');
        expect(removeGrantQuestion({ ...g, liveCertificates: 1 })).toContain('1 live certificate carries the name under this grant. It is revoked, unless');
        expect(removeGrantQuestion({ ...g, liveCertificates: 3 })).toContain('3 live certificates carry the name under this grant. Each is revoked, unless');
    });

    it('reports a revoke-all, with what was left for want of rights', () => {
        expect(revokeAllSentence(2, 0)).toBe('Revoked 2 certificates.');
        expect(revokeAllSentence(1, 1)).toBe('Revoked 1 certificate. 1 was left, because you may not revoke on its SSH CA.');
        expect(revokeAllSentence(0, 2)).toBe('No certificate was revoked. 2 were left, because you may not revoke on their SSH CA.');
    });
});

function cert(over: Partial<SshCertificateView>): SshCertificateView {
    return {
        id: 'c1', sshCaKeyId: 'k1', certificateType: 'user', keyId: 'alice', serialNumber: 8841, principals: '["alice","root"]',
        validAfter: '2026-10-07T09:50:00Z', validBefore: '2026-10-07T17:55:00Z', isRevoked: false, ...over,
    };
}

describe('who a certificate was issued to and by', () => {
    it('names a user, and says when the user has since been deleted', () => {
        const c = cert({ subject: { kind: 'user', userId: 'u1', username: 'alice' } });
        expect(issuedToText(c)).toBe('alice');
        expect(issuedToDetail(c)).toBe('alice, a user of this console');
        expect(issuedToDetail(cert({ subject: { kind: 'user', userId: null, username: 'alice' } }))).toBe('alice, a user who has since been deleted');
    });

    it('names a service identity as hosts log it', () => {
        const c = cert({ keyId: 'svc:backup', subject: { kind: 'service', serviceLabel: 'backup' } });
        expect(issuedToText(c)).toBe('svc:backup');
        expect(issuedToDetail(c)).toBe('svc:backup, a service identity with no account');
    });

    it('names a host by its first hostname', () => {
        const c = cert({ certificateType: 'host', keyId: 'web01.example.com', principals: '["web01.example.com","web01"]', subject: { kind: 'host' } });
        expect(issuedToText(c)).toBe('web01.example.com');
        expect(issuedToDetail(c)).toBe('web01.example.com, a host');
    });

    it('says a subject from before login names is not recorded, never the free text of its key id', () => {
        const c = cert({ keyId: 'root', subject: { kind: 'unknown' }, loginNameGrounds: null });
        expect(issuedToText(c)).toBe(NOT_RECORDED);
        expect(issuedToDetail(c)).toBe(`${NOT_RECORDED}. ${BEFORE_LOGIN_NAMES}.`);
    });

    it('marks self-service, and adds the address only in the detail', () => {
        const self = cert({ issuedBy: { userId: 'u1', username: 'alice', selfService: true, sourceIp: '192.0.2.10' } });
        expect(issuedByText(self)).toBe('alice (self-service)');
        expect(issuedByDetail(self)).toBe('alice, self-service, from 192.0.2.10');
        const admin = cert({ issuedBy: { userId: 'a1', username: 'edward', selfService: false, sourceIp: null } });
        expect(issuedByText(admin)).toBe('edward');
        expect(issuedByDetail(admin)).toBe('edward');
        expect(issuedByText(cert({ issuedBy: { userId: null, username: null } }))).toBe(NOT_RECORDED);
        expect(issuedByText(cert({}))).toBe(NOT_RECORDED);
    });

    it('takes the status the API gives, and works it out for a row without one', () => {
        expect(certificateStatus(cert({ status: 'revoked' }), NOW)).toBe('revoked');
        expect(certificateStatus(cert({}), NOW)).toBe('active');
        expect(certificateStatus(cert({ validBefore: '2026-10-07T09:59:59Z' }), NOW)).toBe('expired');
        expect(certificateStatus(cert({ isRevoked: true }), NOW)).toBe('revoked');
    });

    it('gives an expired certificate a grey badge and a revoked one a red one', () => {
        expect(certificateBadge('active')).toEqual({ status: 'active', label: 'Active' });
        expect(certificateBadge('expired')).toEqual({ status: 'disabled', label: 'Expired' });
        expect(certificateBadge('revoked')).toEqual({ status: 'revoked', label: 'Revoked' });
    });
});

describe('how long a certificate may last', () => {
    const alice = { name: 'alice', maxValidityHours: 720 };
    const deploy = { name: 'deploy', maxValidityHours: 24 };
    const root = { name: 'root', maxValidityHours: 8 };

    it('is the ceiling with no name ticked, or with names that allow as much', () => {
        expect(validityLimit([], 720, NOW)).toEqual({ maxHours: 720, by: 'ceiling', loginName: null, withoutHours: null, endsAt: null });
        expect(validityLimit([alice], 720, NOW).by).toBe('ceiling');
        expect(validityLimitText(validityLimit([alice], 720, NOW))).toBeNull();
    });

    it('is the smallest limit among the ticked names, naming that name and what the limit is without it', () => {
        const limit = validityLimit([alice, deploy, root], 720, NOW);
        expect(limit).toEqual({ maxHours: 8, by: 'hours', loginName: 'root', withoutHours: 24, endsAt: null });
        expect(validityLimitText(limit)).toBe('At most 8 hours, because root is ticked. Without it this certificate could last 24 hours.');
        expect(defaultValidity(limit)).toBe('8');
    });

    it('never goes over the ceiling of the profiles and the SSH CA', () => {
        expect(validityLimit([alice, deploy], 12, NOW)).toMatchObject({ maxHours: 12, by: 'ceiling', loginName: null });
    });

    it('leaves the second sentence out when another ticked name has the same limit', () => {
        const limit = validityLimit([root, { name: 'postgres', maxValidityHours: 8 }], 720, NOW);
        expect(limit).toMatchObject({ maxHours: 8, loginName: 'root', withoutHours: 8 });
        expect(validityLimitText(limit)).toBe('At most 8 hours, because root is ticked.');
    });

    it('stops at the end of a grant, counted from the certificate\'s start five minutes back', () => {
        // The certificate starts at 09:55; the grant ends at 12:55, so three whole hours fit.
        const limit = validityLimit([alice, { ...root, expiresAt: '2026-10-07T12:55:00Z' }], 720, NOW);
        expect(limit).toMatchObject({ maxHours: 3, by: 'end', loginName: 'root', withoutHours: 720, endsAt: '2026-10-07T12:55:00Z' });
        expect(validityLimitText(limit, day)).toBe('At most 3 hours can be asked for, because root is ticked and its grant ends on 2026-10-07. '
            + 'Without it this certificate could last 720 hours. Left empty, the certificate ends when the grant does.');
        expect(validityLimit([{ ...root, expiresAt: '2026-10-07T12:54:59Z' }], 720, NOW).maxHours).toBe(2);
    });

    it('starts the field empty where a grant\'s end sets the limit, since empty then lasts longest', () => {
        const limit = validityLimit([{ ...root, expiresAt: '2026-10-07T10:30:00Z' }], 720, NOW);
        expect(limit).toMatchObject({ maxHours: 0, by: 'end' });
        expect(defaultValidity(limit)).toBe('');
        expect(validityLimitText(limit, day)).toContain('Less than an hour can be asked for');
        expect(validityProblem('1', limit)).toBe('Less than an hour is left before a grant ends. Leave the field empty.');
        expect(validityProblem('', limit)).toBeNull();
    });

    it('prefers the limit in hours when the end allows as much', () => {
        expect(validityLimit([{ ...root, expiresAt: '2026-10-14T00:00:00Z' }], 720, NOW)).toMatchObject({ maxHours: 8, by: 'hours' });
    });

    it('checks what is typed against the limit', () => {
        const limit = validityLimit([root], 720, NOW);
        expect(validityProblem('8', limit)).toBeNull();
        expect(validityProblem('', limit)).toBeNull();
        expect(validityProblem('9', limit)).toBe('9 hours is over the most allowed here, 8.');
        expect(validityProblem('0', limit)).not.toBeNull();
    });
});

describe('the profile choices of the request form', () => {
    const combo = (r: string, s: string, c: string, over: Partial<SshRequestProfileCombination> = {}): SshRequestProfileCombination => ({
        requestProfileId: r, requestProfileName: `request ${r}`, signingProfileId: s, signingProfileName: `signing ${s}`,
        certProfileId: c, certProfileName: `cert ${c}`, maxValidityHours: 24, maxPrincipals: 10, unavailableLoginNames: [], ...over,
    });
    const combos = [combo('r1', 's1', 'c1'), combo('r1', 's1', 'c2'), combo('r2', 's2', 'c1')];

    it('lists each profile once', () => {
        expect(requestProfileChoices(combos).map((p) => p.id)).toEqual(['r1', 'r2']);
        expect(signingProfileChoices(combos, 'r1').map((p) => p.id)).toEqual(['s1']);
        expect(certProfileChoices(combos, 'r1', 's1').map((p) => p.id)).toEqual(['c1', 'c2']);
    });

    it('takes the first combination with nothing chosen, so one combination needs no picker', () => {
        expect(chosenCombination(combos, {})).toBe(combos[0]);
        expect(chosenCombination([combos[2]], {})).toBe(combos[2]);
        expect(chosenCombination([], {})).toBeNull();
    });

    it('follows each choice, and drops a later choice the earlier one no longer offers', () => {
        expect(chosenCombination(combos, { requestProfileId: 'r1', certProfileId: 'c2' })).toBe(combos[1]);
        expect(chosenCombination(combos, { requestProfileId: 'r2', signingProfileId: 's1', certProfileId: 'c2' })).toBe(combos[2]);
        expect(chosenCombination(combos, { requestProfileId: 'gone' })).toBe(combos[0]);
    });
});

describe('a host log line', () => {
    const LINE = 'Oct  7 09:58:14 web01 sshd[21877]: Accepted publickey for root from 192.0.2.10 port 51122 ssh2: '
        + 'ED25519-CERT SHA256:kkk ID alice (serial 8841) CA ED25519 SHA256:ccc';

    it('gives the account, the key id, the serial and the CA fingerprint', () => {
        expect(parseSshdLogLine(LINE)).toEqual({ kind: 'certificate', account: 'root', keyId: 'alice', serial: '8841', caKeyType: 'ED25519', caFingerprint: 'SHA256:ccc' });
    });

    it('reads a line with no syslog prefix, with surrounding space and a line break', () => {
        const bare = '  Accepted publickey for deploy from 2001:db8::1 port 22 ssh2: ECDSA-CERT SHA256:kkk ID svc:backup (serial 12) CA RSA SHA256:ccc\r\n';
        expect(parseSshdLogLine(bare)).toMatchObject({ kind: 'certificate', account: 'deploy', keyId: 'svc:backup', serial: '12', caKeyType: 'RSA' });
    });

    it('keeps a serial too large for a number exact', () => {
        const big = LINE.replace('8841', '18446744073709551615');
        expect(parseSshdLogLine(big)).toMatchObject({ serial: '18446744073709551615' });
    });

    it('reads a key id with spaces, from before the CA wrote it', () => {
        expect(parseSshdLogLine(LINE.replace('ID alice', 'ID alice laptop key'))).toMatchObject({ keyId: 'alice laptop key', serial: '8841' });
    });

    it('takes the certificate part from the end of the line, where sshd writes it', () => {
        const forged = LINE.replace('ID alice', 'ID bob (serial 1) CA ED25519 SHA256:other');
        expect(parseSshdLogLine(forged)).toMatchObject({ keyId: 'bob (serial 1) CA ED25519 SHA256:other', serial: '8841', caFingerprint: 'SHA256:ccc' });
    });

    it('passes no fingerprint that is not SHA256', () => {
        expect(parseSshdLogLine(LINE.replace('SHA256:ccc', 'MD5:aa:bb'))).toMatchObject({ kind: 'certificate', caFingerprint: null });
    });

    it('says a login with a plain public key or a password has no certificate', () => {
        const plain = 'Accepted publickey for root from 192.0.2.10 port 51122 ssh2: ED25519 SHA256:kkk';
        expect(parseSshdLogLine(plain)).toEqual({ kind: 'noCertificate', account: 'root', method: 'publickey' });
        expect(logLineProblem(parseSshdLogLine(plain))).toContain('a login without a certificate:');
        const password = 'Accepted password for root from 192.0.2.10 port 51122 ssh2';
        expect(logLineProblem(parseSshdLogLine(password))).toContain('a login without a certificate (password):');
    });

    it('says so when no login can be read, and nothing for an empty field or a good line', () => {
        expect(parseSshdLogLine('hello world')).toEqual({ kind: 'unreadable' });
        expect(logLineProblem({ kind: 'unreadable' })).toContain('No login could be read');
        expect(parseSshdLogLine('  \n ')).toEqual({ kind: 'empty' });
        expect(logLineProblem({ kind: 'empty' })).toBeNull();
        expect(logLineProblem(parseSshdLogLine(LINE))).toBeNull();
    });

    it('asks the find route for the three values', () => {
        const line = parseSshdLogLine(LINE);
        if (line.kind !== 'certificate') throw new Error('expected a certificate line');
        expect(findQuery(line)).toBe('serial=8841&keyId=alice&caFingerprint=SHA256%3Accc');
        expect(findQuery({ ...line, keyId: 'svc:a b', caFingerprint: null })).toBe('serial=8841&keyId=svc%3Aa+b');
    });
});

describe('key types and key files', () => {
    it('names a key type as sshd prints it', () => {
        expect(sshdKeyType('ssh-ed25519 AAAA you@laptop')).toBe('ED25519');
        expect(sshdKeyType('ecdsa-sha2-nistp256 AAAA')).toBe('ECDSA');
        expect(sshdKeyType('ssh-rsa AAAA')).toBe('RSA');
        expect(sshdKeyType('sk-ssh-ed25519@openssh.com AAAA')).toBe('ED25519-SK');
        expect(sshdKeyType('sk-ecdsa-sha2-nistp256@openssh.com AAAA')).toBe('ECDSA-SK');
        expect(sshdKeyType('ed25519')).toBe('ED25519');
        expect(sshdKeyType('rsa')).toBe('RSA');
        expect(sshdKeyType('')).toBe('KEY');
        expect(sshdKeyType(null)).toBe('KEY');
    });

    it('guesses the usual private key file, defaulting to ed25519', () => {
        expect(defaultKeyFile('ssh-ed25519 AAAA')).toBe('id_ed25519');
        expect(defaultKeyFile('ssh-rsa AAAA')).toBe('id_rsa');
        expect(defaultKeyFile('ecdsa-sha2-nistp384 AAAA')).toBe('id_ecdsa');
        expect(defaultKeyFile('sk-ssh-ed25519@openssh.com AAAA')).toBe('id_ed25519_sk');
        expect(defaultKeyFile(undefined)).toBe('id_ed25519');
    });

    it('names the host key file in /etc/ssh, defaulting to ed25519', () => {
        expect(defaultHostKeyFile('ssh-ed25519 AAAA')).toBe('ssh_host_ed25519_key');
        expect(defaultHostKeyFile('ssh-rsa AAAA')).toBe('ssh_host_rsa_key');
        expect(defaultHostKeyFile('ecdsa-sha2-nistp256 AAAA')).toBe('ssh_host_ecdsa_key');
        expect(defaultHostKeyFile(undefined)).toBe('ssh_host_ed25519_key');
    });
});

describe('rights on an SSH CA key, held on the CA it belongs to', () => {
    const caps: EffectiveCapabilities = {
        system: ['cert.view'],
        cas: [
            { id: 'ca1', label: 'prod-user-ca', name: 'prod-user-ca', isSshCa: true, spaceId: null, spaceName: '', spaceSlug: '', capabilities: ['cert.view', 'ca.manage'] },
            { id: 'ca2', label: 'lab-user-ca', name: 'lab-user-ca', isSshCa: true, spaceId: null, spaceName: '', spaceSlug: '', capabilities: ['cert.view'] },
            { id: 'ca3', label: 'issuing', name: 'prod-user-ca', isSshCa: false, spaceId: 's1', spaceName: 'A', spaceSlug: 'a', capabilities: ['ca.manage'] },
        ],
    };

    it('holds what is held on that SSH CA, and what is held at system scope', () => {
        expect(canOnSshCa(caps, { certificateAuthorityId: 'ca1' }, 'ca.manage')).toBe(true);
        expect(canOnSshCa(caps, { certificateAuthorityId: 'ca2' }, 'ca.manage')).toBe(false);
        expect(canOnSshCa(caps, { certificateAuthorityId: 'ca2' }, 'cert.view')).toBe(true);
        expect(canOnSshCa({ system: ['ca.manage'], cas: [] }, { certificateAuthorityId: 'anything' }, 'ca.manage')).toBe(true);
    });

    it('does not read another CA of the same name, and holds nothing without capabilities or a CA id', () => {
        expect(canOnSshCa({ system: [], cas: [caps.cas[2]] }, { certificateAuthorityId: 'ca1' }, 'ca.manage')).toBe(false);
        expect(canOnSshCa(null, { certificateAuthorityId: 'ca1' }, 'ca.manage')).toBe(false);
        expect(canOnSshCa(caps, null, 'ca.manage')).toBe(false);
        expect(canOnSshCa(caps, {}, 'ca.manage')).toBe(false);
    });
});
