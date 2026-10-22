import { describe, expect, it } from 'vitest';
import * as signing from '@adminui/pages/profiles/sshSigningProfile';
import * as cert from '@adminui/pages/profiles/sshCertProfile';
import * as request from '@adminui/pages/profiles/sshRequestProfile';
import { NAME_REQUIRED_REASON } from '@adminui/pages/profiles/profileFormCore';
import { bodyKeys, dtoKeys, jsonList } from './profileFormKit';

/**
 * The three SSH profile form models behind /profiles/ssh-<type>/new and /profiles/ssh-<type>/:id.
 *
 * The SSH DTOs are declared in ModularCA.API/Controllers/v1/Admin/AdminSshProfileController.cs,
 * outside ModularCA.Shared/Models, so scripts/generate-shared-types.mjs does not emit them. The key
 * lists below are copied from those C# classes; dtoKeys ties each to the TypeScript mirror the
 * model declares, so the mirror and the list cannot drift apart silently either.
 *
 * Their update DTOs are patches (null leaves a value unchanged), which is why the update bodies
 * send text fields as strings: clearing a description or a force command has to reach the server.
 */

// CreateSshSigningProfileRequest / UpdateSshSigningProfileRequest (AdminSshProfileController.cs).
const SSH_SIGNING_KEYS = ['name', 'description', 'sshCaKeyId', 'maxValidityHours', 'allowUserCerts', 'allowHostCerts', 'forceCommand', 'sourceAddressRestrictions', 'defaultExtensions'].sort();
// CreateSshCertProfileRequest / UpdateSshCertProfileRequest (AdminSshProfileController.cs).
const SSH_CERT_KEYS = ['name', 'description', 'allowedPrincipalPatterns', 'maxPrincipals', 'allowedExtensions', 'requiredExtensions', 'maxValidityHours', 'certificateType'].sort();
// CreateSshRequestProfileRequest / UpdateSshRequestProfileRequest (AdminSshProfileController.cs).
const SSH_REQUEST_KEYS = ['name', 'description', 'allowedSshSigningProfileIds', 'allowedSshCertProfileIds', 'requireApproval', 'maxValidityHours', 'certificateAuthorityId', 'certificateType'].sort();

describe('the SSH body mirrors match the C# DTO lists', () => {
    it('signing', () => {
        expect(dtoKeys<signing.CreateSshSigningProfileBody>({ name: true, description: true, sshCaKeyId: true, maxValidityHours: true, allowUserCerts: true, allowHostCerts: true, forceCommand: true, sourceAddressRestrictions: true, defaultExtensions: true })).toEqual(SSH_SIGNING_KEYS);
        expect(dtoKeys<signing.UpdateSshSigningProfileBody>({ name: true, description: true, sshCaKeyId: true, maxValidityHours: true, allowUserCerts: true, allowHostCerts: true, forceCommand: true, sourceAddressRestrictions: true, defaultExtensions: true })).toEqual(SSH_SIGNING_KEYS);
    });
    it('cert', () => {
        expect(dtoKeys<cert.CreateSshCertProfileBody>({ name: true, description: true, allowedPrincipalPatterns: true, maxPrincipals: true, allowedExtensions: true, requiredExtensions: true, maxValidityHours: true, certificateType: true })).toEqual(SSH_CERT_KEYS);
        expect(dtoKeys<cert.UpdateSshCertProfileBody>({ name: true, description: true, allowedPrincipalPatterns: true, maxPrincipals: true, allowedExtensions: true, requiredExtensions: true, maxValidityHours: true, certificateType: true })).toEqual(SSH_CERT_KEYS);
    });
    it('request', () => {
        expect(dtoKeys<request.CreateSshRequestProfileBody>({ name: true, description: true, allowedSshSigningProfileIds: true, allowedSshCertProfileIds: true, requireApproval: true, maxValidityHours: true, certificateAuthorityId: true, certificateType: true })).toEqual(SSH_REQUEST_KEYS);
        expect(dtoKeys<request.UpdateSshRequestProfileBody>({ name: true, description: true, allowedSshSigningProfileIds: true, allowedSshCertProfileIds: true, requireApproval: true, maxValidityHours: true, certificateAuthorityId: true, certificateType: true })).toEqual(SSH_REQUEST_KEYS);
    });
});

describe('SSH signing profile form', () => {
    const stored = {
        id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
        name: 'Ops signer',
        description: 'Operations team',
        sshCaKeyId: '0b6f3f0e-2222-4c4c-9a9a-000000000002',
        maxValidityHours: 24,
        allowUserCerts: false,
        allowHostCerts: true,
        forceCommand: '/usr/bin/rsync',
        sourceAddressRestrictions: '["10.0.0.0/8","192.168.1.0/24"]',
        defaultExtensions: '["permit-pty","permit-port-forwarding"]',
        createdAt: '2026-09-01T00:00:00Z',
    };

    it('posts exactly the create DTO fields with the server defaults from an empty form', () => {
        const body = signing.formToCreateBody(signing.emptyForm());
        expect(bodyKeys(body)).toEqual(SSH_SIGNING_KEYS);
        expect(body).toEqual({
            name: '', description: null, sshCaKeyId: '', maxValidityHours: 720, allowUserCerts: true,
            allowHostCerts: false, forceCommand: null, sourceAddressRestrictions: '[]', defaultExtensions: '["permit-pty"]',
        });
    });

    it('puts exactly the update DTO fields', () => {
        expect(bodyKeys(signing.formToUpdateBody(signing.formFromProfile(stored)))).toEqual(SSH_SIGNING_KEYS);
    });

    it('preserves every field of a stored profile through load and save', () => {
        const body = signing.formToUpdateBody(signing.formFromProfile(stored));
        expect(body).toMatchObject({
            name: stored.name, description: stored.description, sshCaKeyId: stored.sshCaKeyId,
            maxValidityHours: 24, allowUserCerts: false, allowHostCerts: true, forceCommand: '/usr/bin/rsync',
        });
        expect(jsonList(body.sourceAddressRestrictions)).toEqual(jsonList(stored.sourceAddressRestrictions));
        expect(jsonList(body.defaultExtensions)).toEqual(jsonList(stored.defaultExtensions));
        expect(signing.formFromProfile(body)).toEqual(signing.formFromProfile(stored));
    });

    it('sends a cleared force command and description so the patch clears them', () => {
        const body = signing.formToUpdateBody({ ...signing.formFromProfile(stored), forceCommand: '', description: '' });
        expect(body.forceCommand).toBe('');
        expect(body.description).toBe('');
    });

    it('falls back to 720 hours for blank or zero', () => {
        expect(signing.formToCreateBody({ ...signing.emptyForm(), maxValidityHours: '' }).maxValidityHours).toBe(720);
        expect(signing.formToUpdateBody({ ...signing.emptyForm(), maxValidityHours: '0' }).maxValidityHours).toBe(720);
    });

    it('needs a name, a CA key and at least one certificate kind, in both modes', () => {
        expect(signing.validate(signing.emptyForm(), 'create')).toEqual([NAME_REQUIRED_REASON, signing.CA_KEY_REASON]);
        const ok = { ...signing.emptyForm(), name: 'S', sshCaKeyId: 'k' };
        expect(signing.validate(ok, 'create')).toEqual([]);
        expect(signing.validate({ ...ok, allowUserCerts: false, allowHostCerts: false }, 'create')).toEqual([signing.SIGNS_NOTHING_REASON]);
        expect(signing.validate({ ...ok, allowUserCerts: false, allowHostCerts: false }, 'edit')).toEqual([signing.SIGNS_NOTHING_REASON]);
    });

    it('blocks a source address sshd would reject, including a range with host bits set', () => {
        const ok = { ...signing.emptyForm(), name: 'S', sshCaKeyId: 'k' };
        expect(signing.validate({ ...ok, sourceAddressRestrictions: ['10.0.0.0/8', '2001:db8::/32', '192.168.1.5'] }, 'edit')).toEqual([]);
        expect(signing.validate({ ...ok, sourceAddressRestrictions: ['10.0.0.1/8'] }, 'edit')).toEqual([signing.SOURCE_ADDRESS_REASON]);
        expect(signing.validate({ ...ok, sourceAddressRestrictions: ['office'] }, 'create')).toEqual([signing.SOURCE_ADDRESS_REASON]);
    });

    it('sends the source address list as a JSON array', () => {
        const body = signing.formToCreateBody({ ...signing.emptyForm(), sourceAddressRestrictions: ['10.0.0.0/8', '::1'] });
        expect(jsonList(body.sourceAddressRestrictions)).toEqual(['10.0.0.0/8', '::1']);
    });
});

describe('SSH cert profile form', () => {
    const stored = {
        id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
        name: 'Developers',
        description: 'Dev logins',
        allowedPrincipalPatterns: '["^[a-z_][a-z0-9_-]*$","^admin$"]',
        maxPrincipals: 3,
        allowedExtensions: '["permit-pty","permit-agent-forwarding"]',
        requiredExtensions: '["permit-pty"]',
        maxValidityHours: 8,
    };

    it('posts exactly the create DTO fields with the server defaults from an empty form', () => {
        const body = cert.formToCreateBody(cert.emptyForm());
        expect(bodyKeys(body)).toEqual(SSH_CERT_KEYS);
        expect(body).toEqual({
            name: '', description: null, allowedPrincipalPatterns: '[]', maxPrincipals: 10,
            allowedExtensions: JSON.stringify(cert.DEFAULT_ALLOWED_EXTENSIONS), requiredExtensions: '[]', maxValidityHours: 720,
            certificateType: 'either',
        });
    });

    it('loads the certificate type, sends it on create and update, and sends either to clear it', () => {
        expect(cert.formFromProfile(stored).certificateType).toBe('either');
        expect(cert.formFromProfile({ ...stored, certificateType: null }).certificateType).toBe('either');
        expect(cert.formFromProfile({ ...stored, certificateType: 'host' }).certificateType).toBe('host');
        const user = { ...cert.formFromProfile(stored), certificateType: 'user' as const };
        expect(cert.formToCreateBody(user).certificateType).toBe('user');
        expect(cert.formToUpdateBody(user).certificateType).toBe('user');
        // The update is a patch, where null leaves the type alone: clearing it has to send the word.
        expect(cert.formToUpdateBody({ ...cert.formFromProfile({ ...stored, certificateType: 'host' }), certificateType: 'either' }).certificateType).toBe('either');
    });

    it('puts exactly the update DTO fields', () => {
        expect(bodyKeys(cert.formToUpdateBody(cert.formFromProfile(stored)))).toEqual(SSH_CERT_KEYS);
    });

    it('preserves every field of a stored profile through load and save', () => {
        const body = cert.formToUpdateBody(cert.formFromProfile(stored));
        expect(body).toMatchObject({ name: stored.name, description: stored.description, maxPrincipals: 3, maxValidityHours: 8 });
        expect(jsonList(body.allowedPrincipalPatterns)).toEqual(jsonList(stored.allowedPrincipalPatterns));
        expect(jsonList(body.allowedExtensions)).toEqual(jsonList(stored.allowedExtensions));
        expect(jsonList(body.requiredExtensions)).toEqual(jsonList(stored.requiredExtensions));
        expect(cert.formFromProfile(body)).toEqual(cert.formFromProfile(stored));
    });

    it('sends a cleared description so the patch clears it', () => {
        expect(cert.formToUpdateBody({ ...cert.formFromProfile(stored), description: '' }).description).toBe('');
    });

    it('blocks a required extension the allowed list excludes, but not when Allowed is unrestricted', () => {
        const named = { ...cert.emptyForm(), name: 'C' };
        expect(cert.validate({ ...named, allowedExtensions: ['permit-pty'], requiredExtensions: ['permit-user-rc'] }, 'create'))
            .toEqual([cert.REQUIRED_NOT_ALLOWED_REASON]);
        expect(cert.validate({ ...named, allowedExtensionsMode: 'any', allowedExtensions: [], requiredExtensions: ['permit-user-rc'] }, 'edit')).toEqual([]);
        expect(cert.validate(cert.emptyForm(), 'edit')).toEqual([NAME_REQUIRED_REASON]);
    });

    it('loads an empty Allowed list as Any and a non-empty one as Only these', () => {
        expect(cert.formFromProfile({ ...stored, allowedExtensions: '[]' }).allowedExtensionsMode).toBe('any');
        expect(cert.formFromProfile(stored).allowedExtensionsMode).toBe('only');
    });

    it('saves Any as an empty Allowed list, whatever is still ticked underneath', () => {
        const form = { ...cert.formFromProfile(stored), allowedExtensionsMode: 'any' as const };
        expect(cert.formToUpdateBody(form).allowedExtensions).toBe('[]');
        expect(cert.validate({ ...form, requiredExtensions: ['permit-user-rc'] }, 'edit')).toEqual([]);
    });

    it('blocks Only these with no allowed extension ticked', () => {
        const named = { ...cert.emptyForm(), name: 'C' };
        expect(cert.validate({ ...named, allowedExtensionsMode: 'only', allowedExtensions: [] }, 'create'))
            .toEqual([cert.ALLOWED_EXTENSIONS_EMPTY_REASON]);
    });

    it('keeps a pattern containing a comma whole and blocks one that does not compile', () => {
        const named = { ...cert.emptyForm(), name: 'C' };
        const body = cert.formToCreateBody({ ...named, allowedPrincipalPatterns: ['^[a-z_][a-z0-9_-]{0,31}$'] });
        expect(jsonList(body.allowedPrincipalPatterns)).toEqual(['^[a-z_][a-z0-9_-]{0,31}$']);
        expect(cert.validate({ ...named, allowedPrincipalPatterns: ['^(admin'] }, 'create')).toEqual([cert.PRINCIPAL_PATTERN_REASON]);
    });

    it('reports which patterns a test principal matches', () => {
        expect(cert.matchPrincipal('alice', ['^admin$', '^[a-z]+$', '^(bad'])).toEqual([
            { pattern: '^admin$', result: 'no-match' },
            { pattern: '^[a-z]+$', result: 'match' },
            { pattern: '^(bad', result: 'invalid' },
        ]);
    });
});

describe('SSH request profile form', () => {
    const stored = {
        id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
        name: 'Developer Access',
        description: 'Self-service',
        allowedSshSigningProfileIds: '["0b6f3f0e-3333-4c4c-9a9a-000000000003"]',
        allowedSshCertProfileIds: '["0b6f3f0e-4444-4c4c-9a9a-000000000004"]',
        requireApproval: true,
        maxValidityHours: 12,
        certificateAuthorityId: '0b6f3f0e-2222-4c4c-9a9a-000000000002',
    };

    it('posts exactly the create DTO fields with the server defaults from an empty form', () => {
        const body = request.formToCreateBody(request.emptyForm());
        expect(bodyKeys(body)).toEqual(SSH_REQUEST_KEYS);
        expect(body).toEqual({
            name: '', description: null, allowedSshSigningProfileIds: '[]', allowedSshCertProfileIds: '[]',
            requireApproval: false, maxValidityHours: 720, certificateAuthorityId: null,
            certificateType: 'either',
        });
    });

    it('loads the certificate type, sends it on create and update, and sends either to clear it', () => {
        expect(request.formFromProfile(stored).certificateType).toBe('either');
        expect(request.formFromProfile({ ...stored, certificateType: 'user' }).certificateType).toBe('user');
        const host = { ...request.formFromProfile(stored), certificateType: 'host' as const };
        expect(request.formToCreateBody(host).certificateType).toBe('host');
        expect(request.formToUpdateBody(host).certificateType).toBe('host');
        expect(request.formToUpdateBody({ ...request.formFromProfile({ ...stored, certificateType: 'user' }), certificateType: 'either' }).certificateType).toBe('either');
    });

    it('never sends the bound-CA bookkeeping field', () => {
        expect(Object.keys(request.formToUpdateBody(request.formFromProfile(stored)))).not.toContain('boundCertificateAuthorityId');
        expect(bodyKeys(request.formToUpdateBody(request.formFromProfile(stored)))).toEqual(SSH_REQUEST_KEYS);
    });

    it('preserves every field of a stored profile through load and save', () => {
        const body = request.formToUpdateBody(request.formFromProfile(stored));
        expect(body).toMatchObject({
            name: stored.name, description: stored.description, requireApproval: true,
            maxValidityHours: 12, certificateAuthorityId: stored.certificateAuthorityId,
        });
        expect(jsonList(body.allowedSshSigningProfileIds)).toEqual(jsonList(stored.allowedSshSigningProfileIds));
        expect(jsonList(body.allowedSshCertProfileIds)).toEqual(jsonList(stored.allowedSshCertProfileIds));
        expect(request.formFromProfile(body)).toEqual(request.formFromProfile(stored));
    });

    it('refuses to unbind a CA-bound profile on edit, which the patch would silently ignore', () => {
        const unbound = { ...request.formFromProfile(stored), certificateAuthorityId: '' };
        expect(request.validate(unbound, 'edit')).toEqual([request.UNBIND_REASON]);
        expect(request.validate({ ...unbound, certificateAuthorityId: 'other-ca' }, 'edit')).toEqual([]);
    });

    it('lets a new or never-bound profile use Any CA', () => {
        const named = { ...request.emptyForm(), name: 'R' };
        expect(request.validate(named, 'create')).toEqual([]);
        expect(request.validate({ ...request.formFromProfile({ ...stored, certificateAuthorityId: null }) }, 'edit')).toEqual([]);
        expect(request.validate(request.emptyForm(), 'create')).toEqual([NAME_REQUIRED_REASON]);
    });
});
