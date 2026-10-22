import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Capabilities } from '@shared/generated';
import { canOnAnySshCa, canUseSshTab, type CaCapabilities, type EffectiveCapabilities } from '@adminui/authz';
import { AUTHORITIES, CA_MANAGE_SPACE, CERTIFICATES, CERTIFICATE_REQUEST, CERT_REQUEST, CERT_VIEW } from '@adminui/gates';
import { ALL_SCOPE, MINE_SCOPE, gateAllows, type Scope } from '@adminui/scope';
import { legacySelfSshPath, legacySshPath } from '@adminui/legacyPaths';
import {
    KIND_TABS, SELF_SSH_CERTIFICATE_ROUTE, SELF_SSH_CERTIFICATES_PATH, SELF_SSH_REQUEST_PATH, SSH_CA_KEYS_PATH, SSH_CA_KEY_ROUTE, SSH_CERTIFICATES_PATH, SSH_CERTIFICATE_ROUTE, SSH_SIGN_PATH, TAB_PARAM,
    activeKindTab, kindTabs, selfSshCertificatePath, signedHandOver, sshCaKeyPath, sshCertificatePath, sshScopeSentence, withKindTab,
} from '@adminui/pages/sshPlaces';
import {
    SSH_PROFILE_TYPE_OPTIONS, certificateTypeFor, defaultSignFor, keySignsFor, profileTypeChoice, profileTypeLabel, profilesForCertificateType, servesCertificateType,
} from '@adminui/pages/sshProfileType';
import { sshKeyChoices } from '@adminui/pages/sshLoginNames';

/**
 * SSH moved out of a menu entry of its own and into tabs on the pages people already use
 * (docs/architecture/ssh-login-names.md, "Where it is in the console"). The router and the pages
 * are not reachable from this React-free project; what is pinned here is what they are built
 * from: the menus, the gates, who is shown which tab, the addresses and the redirects from the
 * old ones, the sentence under a space scope, and which profiles a form offers.
 */
const ca = (id: string, isSshCa: boolean, spaceId: string | null, ...capabilities: CaCapabilities['capabilities']): CaCapabilities => ({
    id, label: id, name: id, isSshCa, spaceId, spaceName: spaceId ? 'Acme' : '', spaceSlug: spaceId ? 'acme' : '', capabilities,
});

const sshOperator: EffectiveCapabilities = { system: [], cas: [ca('fleet-ssh', true, null, Capabilities.CertRevoke, Capabilities.CertView, Capabilities.CertRequest)] };
const sshAuditor: EffectiveCapabilities = { system: [], cas: [ca('fleet-ssh', true, null, Capabilities.CertView, Capabilities.AuditView)] };
const sshRequester: EffectiveCapabilities = { system: [], cas: [ca('fleet-ssh', true, null, Capabilities.CertRequest, Capabilities.CertView)] };
const x509Admin: EffectiveCapabilities = { system: [], cas: [ca('acme-root', false, 's1', Capabilities.CaManage, Capabilities.CertRevoke, Capabilities.CertView, Capabilities.CertRequest)] };
const systemOperator: EffectiveCapabilities = { system: [Capabilities.CaManage], cas: [] };
const systemAdmin: EffectiveCapabilities = {
    system: [Capabilities.SystemManage, Capabilities.CaManage, Capabilities.CertRevoke, Capabilities.CertView, Capabilities.CertRequest], cas: [],
};

const acme: Scope = { kind: 'space', spaceId: 's1', slug: 'acme', name: 'Acme' };
const acmeRoot: Scope = { kind: 'ca', caId: 'acme-root', label: 'acme-root', spaceId: 's1', spaceSlug: 'acme' };
const fleetSsh: Scope = { kind: 'ca', caId: 'fleet-ssh', label: 'fleet-ssh', spaceId: null, spaceSlug: '' };

afterEach(() => vi.unstubAllGlobals());

describe('the menus', () => {
    it('no longer have an SSH entry, and the three pages that carry an SSH tab admit who can use it', async () => {
        // portal.ts reads the address the bundle was loaded under when it is first imported.
        vi.stubGlobal('window', { location: { pathname: '/admin/dashboard', search: '' } });
        const { adminNavSections, userNavSections } = await import('@adminui/nav');
        const adminItems = adminNavSections.flatMap((s) => s.items);
        const userItems = userNavSections.flatMap((s) => s.items);

        expect(adminItems.map((i) => i.name)).not.toContain('SSH CA');
        expect(adminItems.some((i) => i.path === '/ssh' || i.path.startsWith('/ssh/'))).toBe(false);
        expect(userNavSections.map((s) => s.title)).not.toContain('SSH');
        expect(userItems.map((i) => i.name)).not.toContain('SSH Certificates');
        expect(userItems.some((i) => i.path === '/ssh')).toBe(false);

        const gateOf = (path: string) => adminItems.find((i) => i.path === path)?.gate;
        expect(gateOf('/authorities/manage')).toEqual(AUTHORITIES);
        expect(gateOf('/certificates')).toEqual(CERTIFICATES);
        expect(gateOf('/certificates/request')).toEqual(CERTIFICATE_REQUEST);
        // The self-service pages are open to every signed-in user; the tab itself is gated.
        expect(userItems.find((i) => i.path === '/request')?.gate).toBeUndefined();
        expect(userItems.find((i) => i.path === '/certificates')?.gate).toBeUndefined();
    });
});

describe('who is shown an SSH tab', () => {
    it('asks what the routes of each tab ask, on an SSH CA or at system scope', () => {
        expect(canUseSshTab(sshOperator, 'keys')).toBe(true);
        expect(canUseSshTab(sshOperator, 'certificates')).toBe(true);
        expect(canUseSshTab(sshOperator, 'sign')).toBe(true);

        // cert.view lists certificates; it neither lists the keys nor signs.
        expect(canUseSshTab(sshAuditor, 'certificates')).toBe(true);
        expect(canUseSshTab(sshAuditor, 'keys')).toBe(false);
        expect(canUseSshTab(sshAuditor, 'sign')).toBe(false);

        expect(canUseSshTab(systemAdmin, 'keys')).toBe(true);
        expect(canUseSshTab(systemAdmin, 'certificates')).toBe(true);
        expect(canUseSshTab(systemAdmin, 'sign')).toBe(true);

        // System-scoped ca.manage may generate an SSH CA key, so it has the keys tab and no other.
        expect(canUseSshTab(systemOperator, 'keys')).toBe(true);
        expect(canUseSshTab(systemOperator, 'certificates')).toBe(false);
        expect(canUseSshTab(systemOperator, 'sign')).toBe(false);
    });

    it('never counts a right held on an X.509 CA', () => {
        for (const place of ['keys', 'certificates', 'sign', 'selfRequest', 'selfCertificates'] as const) {
            expect(canUseSshTab(x509Admin, place)).toBe(false);
            expect(canUseSshTab(null, place)).toBe(false);
        }
        expect(canOnAnySshCa(x509Admin, Capabilities.CertRevoke)).toBe(false);
        expect(canOnAnySshCa(sshOperator, Capabilities.CertRevoke)).toBe(true);
        expect(canOnAnySshCa(sshOperator, Capabilities.CaManage)).toBe(false);
    });

    it('shows the self-service tabs to who may request from an SSH CA', () => {
        expect(canUseSshTab(sshRequester, 'selfRequest')).toBe(true);
        expect(canUseSshTab(sshRequester, 'selfCertificates')).toBe(true);
        expect(canUseSshTab(sshAuditor, 'selfRequest')).toBe(false);
        expect(canUseSshTab(sshAuditor, 'selfCertificates')).toBe(false);
    });

    it('lists each tab only for who can use it, X.509 first', () => {
        expect(KIND_TABS).toEqual(['X.509', 'SSH']);
        expect(kindTabs({ x509: true, ssh: true })).toEqual(['X.509', 'SSH']);
        expect(kindTabs({ x509: true, ssh: false })).toEqual(['X.509']);
        expect(kindTabs({ x509: false, ssh: true })).toEqual(['SSH']);
        expect(kindTabs({ x509: false, ssh: false })).toEqual([]);
    });

    it('opens on X.509 unless the address asks for a tab the reader has', () => {
        expect(activeKindTab(null, ['X.509', 'SSH'])).toBe('X.509');
        expect(activeKindTab('SSH', ['X.509', 'SSH'])).toBe('SSH');
        expect(activeKindTab('bogus', ['X.509', 'SSH'])).toBe('X.509');
        expect(activeKindTab('SSH', ['X.509'])).toBe('X.509');
        expect(activeKindTab(null, ['SSH'])).toBe('SSH');
        expect(activeKindTab('X.509', ['SSH'])).toBe('SSH');
        expect(activeKindTab('SSH', [])).toBeNull();
    });

    it('carries the tab in the address as the Profiles page does, and leaves the default out', () => {
        expect(TAB_PARAM).toBe('tab');
        expect(withKindTab('?page=2&space=acme', 'SSH').toString()).toBe('page=2&space=acme&tab=SSH');
        expect(withKindTab('?tab=SSH&page=2', 'X.509').toString()).toBe('page=2');
        expect(withKindTab(new URLSearchParams('tab=SSH'), 'SSH').toString()).toBe('tab=SSH');
    });
});

describe('the gates of the pages that carry an SSH tab', () => {
    it('admit the X.509 rule under the scope, or the SSH tab under any console scope', () => {
        // An SSH operator holds no ca.manage, and opens Authorities for its SSH tab.
        expect(gateAllows(sshOperator, CA_MANAGE_SPACE, ALL_SCOPE)).toBe(false);
        expect(gateAllows(sshOperator, AUTHORITIES, ALL_SCOPE)).toBe(true);
        expect(gateAllows(sshOperator, AUTHORITIES, fleetSsh)).toBe(true);
        expect(gateAllows(sshOperator, AUTHORITIES, acme)).toBe(true);
        expect(gateAllows(sshOperator, CERTIFICATE_REQUEST, ALL_SCOPE)).toBe(true);

        // An SSH auditor lists certificates and can neither sign nor list keys.
        expect(gateAllows(sshAuditor, CERTIFICATES, fleetSsh)).toBe(true);
        expect(gateAllows(sshAuditor, CERTIFICATE_REQUEST, fleetSsh)).toBe(false);
        expect(gateAllows(sshAuditor, AUTHORITIES, fleetSsh)).toBe(false);

        // An X.509 administrator passes by the X.509 rule alone, as before.
        expect(gateAllows(x509Admin, AUTHORITIES, acmeRoot)).toBe(gateAllows(x509Admin, CA_MANAGE_SPACE, acmeRoot));
        expect(gateAllows(x509Admin, CERTIFICATES, acme)).toBe(gateAllows(x509Admin, CERT_VIEW, acme));
        expect(gateAllows(x509Admin, CERTIFICATE_REQUEST, acme)).toBe(gateAllows(x509Admin, CERT_REQUEST, acme));
        expect(gateAllows(x509Admin, AUTHORITIES, acmeRoot)).toBe(true);
    });

    it('keep the X.509 gates as they were, and admit nobody under the self-service scope', () => {
        expect(AUTHORITIES).toEqual({ ...CA_MANAGE_SPACE, ssh: 'keys' });
        expect(CERTIFICATES).toEqual({ ...CERT_VIEW, ssh: 'certificates' });
        expect(CERTIFICATE_REQUEST).toEqual({ ...CERT_REQUEST, ssh: 'sign' });
        expect(CA_MANAGE_SPACE.ssh).toBeUndefined();
        expect(CERT_VIEW.ssh).toBeUndefined();
        expect(CERT_REQUEST.ssh).toBeUndefined();
        expect(gateAllows(sshOperator, AUTHORITIES, MINE_SCOPE)).toBe(false);
        expect(gateAllows(systemAdmin, CERTIFICATES, MINE_SCOPE)).toBe(false);
    });
});

describe('the addresses', () => {
    it('put each SSH tab on the page it belongs to', () => {
        expect(SSH_CA_KEYS_PATH).toBe('/authorities/manage?tab=SSH');
        expect(SSH_CERTIFICATES_PATH).toBe('/certificates?tab=SSH');
        expect(SSH_SIGN_PATH).toBe('/certificates/request?tab=SSH');
        expect(SELF_SSH_REQUEST_PATH).toBe('/request?tab=SSH');
        expect(SELF_SSH_CERTIFICATES_PATH).toBe('/certificates?tab=SSH');
        for (const path of [SSH_CA_KEYS_PATH, SSH_CERTIFICATES_PATH, SSH_SIGN_PATH, SELF_SSH_REQUEST_PATH, SELF_SSH_CERTIFICATES_PATH]) {
            expect(activeKindTab(new URL(path, 'https://x').searchParams.get(TAB_PARAM), KIND_TABS)).toBe('SSH');
        }
    });

    it('put a key under Authorities and a certificate under Certificates', () => {
        expect(SSH_CA_KEY_ROUTE).toBe('/authorities/ssh/:id');
        expect(SSH_CERTIFICATE_ROUTE).toBe('/certificates/ssh/:id');
        expect(sshCaKeyPath('0b6f3f0e-1111-4c4c-9a9a-000000000001')).toBe('/authorities/ssh/0b6f3f0e-1111-4c4c-9a9a-000000000001');
        expect(sshCertificatePath({ id: 'c1', sshCaKeyId: 'k1' })).toBe('/certificates/ssh/c1?caKey=k1');
        expect(sshCertificatePath({ id: 'c1', sshCaKeyId: 'k1' }, 'root')).toBe('/certificates/ssh/c1?caKey=k1&used=root');
        expect(sshCertificatePath({ id: 'c1' })).toBe('/certificates/ssh/c1');
        expect(SELF_SSH_CERTIFICATE_ROUTE).toBe('/certificates/ssh/:id');
        expect(selfSshCertificatePath('c1')).toBe('/certificates/ssh/c1');
    });

    it('hand a signed certificate only to the page of that certificate', () => {
        const signed = { id: 'c1', signedCertificate: 'ssh-ed25519-cert-v01@openssh.com AAAA', publicKey: 'ssh-ed25519 AAAA', forUser: 'alice' };
        expect(signedHandOver({ signed }, 'c1')).toEqual(signed);
        expect(signedHandOver({ signed }, 'c2')).toBeNull();
        expect(signedHandOver({ signed: { ...signed, signedCertificate: '' } }, 'c1')).toBeNull();
        expect(signedHandOver(null, 'c1')).toBeNull();
        expect(signedHandOver({ signed: { id: 'c1', signedCertificate: 'x' } }, 'c1')).toEqual({ id: 'c1', signedCertificate: 'x', publicKey: '', forUser: null });
    });

    it('redirect the old administration addresses to their new homes, query string kept', () => {
        expect(legacySshPath('/ssh')).toBe(SSH_CERTIFICATES_PATH);
        expect(legacySshPath('/ssh/')).toBe(SSH_CERTIFICATES_PATH);
        expect(legacySshPath('/ssh', '?space=acme')).toBe('/certificates?space=acme&tab=SSH');
        expect(legacySshPath('/ssh/ca-keys/abc')).toBe(sshCaKeyPath('abc'));
        expect(legacySshPath('/ssh/ca-keys/abc', '?scope=all')).toBe('/authorities/ssh/abc?scope=all');
        expect(legacySshPath('/ssh/certs/c1', '?caKey=k1&used=root')).toBe(sshCertificatePath({ id: 'c1', sshCaKeyId: 'k1' }, 'root'));
        expect(legacySshPath('/ssh/certs/c1')).toBe('/certificates/ssh/c1');
    });

    it('redirect the old self-service address to the SSH tab of My Certificates', () => {
        expect(legacySelfSshPath('/ssh')).toBe(SELF_SSH_CERTIFICATES_PATH);
        expect(legacySelfSshPath('/ssh/', '?x=1')).toBe('/certificates?x=1&tab=SSH');
        expect(legacySelfSshPath('/ssh/ca-keys/abc')).toBeNull();
        expect(legacySelfSshPath('/certificates')).toBeNull();
    });

    it('leave every other path alone', () => {
        expect(legacySshPath('/certificates')).toBeNull();
        expect(legacySshPath('/ssh/other')).toBeNull();
        expect(legacySshPath('/ssh/ca-keys/abc/extra')).toBeNull();
        expect(legacySshPath('/sshx')).toBeNull();
        expect(legacySshPath('/authorities/ssh/abc')).toBeNull();
    });

    it('are the ones the two UI guides name, and the guides give no old address as a route', () => {
        const page = (name: string) => readFileSync(resolve(__dirname, `../../../../modularca.docsui/src/pages/${name}`), 'utf8')
            .replace(/&#123;/g, '{').replace(/&#125;/g, '}');
        const admin = page('AdminUiGuide.tsx');
        for (const address of [SSH_CA_KEYS_PATH, SSH_CERTIFICATES_PATH, SSH_SIGN_PATH, SSH_CA_KEY_ROUTE.replace(':id', '{id}'), SSH_CERTIFICATE_ROUTE.replace(':id', '{id}')]) {
            expect(admin).toContain(`/admin${address}`);
        }
        expect(admin).not.toMatch(/Route: \/admin\/ssh\b/);
        const user = page('UserUiGuide.tsx');
        expect(user).toContain(`/user${SELF_SSH_REQUEST_PATH}`);
        expect(user).toContain(`/user${SELF_SSH_CERTIFICATES_PATH}`);
        expect(user).not.toMatch(/Route: \/user\/ssh\b/);
    });
});

describe('the scope sentence', () => {
    it('is said under a space, and under a CA of a space', () => {
        expect(sshScopeSentence(acme)).toBe('SSH CAs belong to the instance, not to a space, so the scope Acme holds none. Change the scope in the top bar to see them.');
        expect(sshScopeSentence(acmeRoot)).toContain('the scope acme-root holds none');
    });

    it('is not said under all CAs, an instance CA or the self-service scope', () => {
        expect(sshScopeSentence(ALL_SCOPE)).toBeNull();
        expect(sshScopeSentence(fleetSsh)).toBeNull();
        expect(sshScopeSentence(MINE_SCOPE)).toBeNull();
    });
});

describe('the profiles a form offers', () => {
    const profiles = [
        { id: 'u', name: 'SSH User Cert - Standard', certificateType: 'user' },
        { id: 'h', name: 'SSH Host Cert - Standard', certificateType: 'host' },
        { id: 'e', name: 'Either, cleared', certificateType: null },
        { id: 'o', name: 'From before the type' },
    ];

    it('are those of the certificate type and those with no type', () => {
        expect(profilesForCertificateType(profiles, 'user').map((p) => p.id)).toEqual(['u', 'e', 'o']);
        expect(profilesForCertificateType(profiles, 'host').map((p) => p.id)).toEqual(['h', 'e', 'o']);
        expect(servesCertificateType({ certificateType: 'host' }, 'user')).toBe(false);
        expect(servesCertificateType({ certificateType: '' }, 'user')).toBe(true);
        expect(servesCertificateType(null, 'host')).toBe(true);
    });

    it('follow who the certificate is for: a service identity carries a user certificate', () => {
        expect(certificateTypeFor('user')).toBe('user');
        expect(certificateTypeFor('service')).toBe('user');
        expect(certificateTypeFor('host')).toBe('host');
        expect(profilesForCertificateType(profiles, certificateTypeFor('service')).map((p) => p.id)).not.toContain('h');
        expect(profilesForCertificateType(profiles, certificateTypeFor('host')).map((p) => p.id)).not.toContain('u');
    });

    it('start on a host for a key that signs host certificates only', () => {
        expect(defaultSignFor({ isUserCa: false, isHostCa: true })).toBe('host');
        expect(defaultSignFor({ isUserCa: true, isHostCa: false })).toBe('user');
        expect(defaultSignFor({ isUserCa: true, isHostCa: true })).toBe('user');
        expect(defaultSignFor({})).toBe('user');
    });

    it('offer only the answers the key signs', () => {
        const userOnly = { isUserCa: true, isHostCa: false };
        expect(keySignsFor(userOnly, 'user')).toBe(true);
        expect(keySignsFor(userOnly, 'service')).toBe(true);
        expect(keySignsFor(userOnly, 'host')).toBe(false);
        expect(keySignsFor({ isUserCa: false, isHostCa: true }, 'service')).toBe(false);
        expect(keySignsFor({}, 'host')).toBe(true);
    });

    it('show a stored type as User, Host or Either', () => {
        expect(SSH_PROFILE_TYPE_OPTIONS.map((o) => `${o.value}=${o.label}`)).toEqual(['user=User', 'host=Host', 'either=Either']);
        expect(profileTypeChoice('user')).toBe('user');
        expect(profileTypeChoice('host')).toBe('host');
        expect(profileTypeChoice(null)).toBe('either');
        expect(profileTypeChoice(undefined)).toBe('either');
        expect(profileTypeChoice('User')).toBe('either');
        expect(profileTypeLabel('host')).toBe('Host');
        expect(profileTypeLabel(null)).toBe('Either');
    });
});

describe('the key filter of the certificate list', () => {
    const fleet = { id: 'k2', name: 'Fleet SSH' };
    const lab = { id: 'k1', name: 'Lab SSH' };

    it('is the key list when it answers, by name', () => {
        expect(sshKeyChoices([lab, fleet], [])).toEqual([fleet, lab]);
        expect(sshKeyChoices([lab], [fleet])).toEqual([lab]);
        expect(sshKeyChoices([], [fleet])).toEqual([]);
    });

    it('is the keys of the certificates seen, each once, for a reader the key list refuses', () => {
        expect(sshKeyChoices(null, [lab, fleet, lab, fleet])).toEqual([fleet, lab]);
        expect(sshKeyChoices(null, [])).toEqual([]);
    });
});
