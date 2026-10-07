import { describe, expect, it } from 'vitest';
import cases from './ldap-mapping-cases.json';
import {
    type MappingGroup, findMappingTarget, isRefusedMappingTarget, mappingRowsFromStored, mappingRowsToJson, mappingTargetOptions,
    mappingTargetProblems, normalizeDnKey, storedMappingPairs, validateLdapDn,
} from '@adminui/pages/ldapMappings';

/**
 * The LDAP Group to Role Mappings editor. Which groups it offers and refuses must match
 * LdapGroupSyncService (target cases shared with LdapMappingTargetTests); stored mappings must
 * round-trip through the rows.
 */

const SPACE = '0b6f3f0e-0000-4c4c-9a9a-00000000000a';
const groups: MappingGroup[] = [
    { name: 'space-acme-user', displayName: 'Acme users', spaceId: SPACE },
    { name: 'space-acme-admin', spaceId: SPACE, isControlled: true },
    { name: 'system-super', spaceId: null, isSystemGroup: true, isSystemTierSuper: true },
    { name: 'instance-readers', spaceId: null },
    { name: 'space-beta-operator', spaceId: SPACE },
];

describe('LDAP mappings: parity with LdapGroupSyncService.IsRefusedMappingTarget', () => {
    it.each(cases.targets)('%j', (c) => {
        expect(isRefusedMappingTarget(c)).toBe(c.refused);
    });
});

describe('LDAP mappings: offered groups', () => {
    it('offers only groups sync can grant: in a space, not system or controlled, by name', () => {
        expect(mappingTargetOptions(groups)).toEqual([
            { value: 'space-acme-user', label: 'space-acme-user (Acme users)' },
            { value: 'space-beta-operator', label: 'space-beta-operator' },
        ]);
    });
});

describe('LDAP mappings: target problems', () => {
    const none = new Set<string>();

    it('refuses a new mapping to a controlled or system group, ignoring case', () => {
        const problems = mappingTargetProblems({ key: 'CN=Admins', value: 'SPACE-ACME-ADMIN' }, groups, none);
        expect(problems.map((p) => p.tone)).toEqual(['error']);
        expect(mappingTargetProblems({ key: 'CN=Root', value: 'system-super' }, groups, none)[0].tone).toBe('error');
    });

    it('only warns about one stored unchanged, as the server lets it pass', () => {
        const stored = storedMappingPairs(mappingRowsFromStored('{"CN=Admins,DC=x":"space-acme-admin"}').rows);
        expect(mappingTargetProblems({ key: 'cn=admins,dc=x', value: 'Space-Acme-Admin' }, groups, stored).map((p) => p.tone)).toEqual(['warning']);
        expect(mappingTargetProblems({ key: 'CN=Other,DC=x', value: 'space-acme-admin' }, groups, stored).map((p) => p.tone)).toEqual(['error']);
    });

    it('warns about a group that does not exist, or an instance group sync never grants', () => {
        expect(mappingTargetProblems({ key: 'CN=a', value: 'CaAdmin' }, groups, none)).toEqual([
            { column: 'value', tone: 'warning', message: 'No group named CaAdmin exists, so this mapping grants nothing.' },
        ]);
        expect(mappingTargetProblems({ key: 'CN=a', value: 'instance-readers' }, groups, none)[0].message).toMatch(/instance group/);
        expect(mappingTargetProblems({ key: 'CN=a', value: 'space-acme-user' }, groups, none)).toEqual([]);
    });

    it('resolves a pre-0.4.0 org- name to its space- group, as sync does', () => {
        expect(findMappingTarget('org-acme-user', groups)?.group.name).toBe('space-acme-user');
        expect(mappingTargetProblems({ key: 'CN=a', value: 'org-acme-user' }, groups, none)[0].message).toMatch(/renamed/);
        expect(findMappingTarget('org-acme-admin', groups)?.renamedFrom).toBe('org-acme-admin');
        expect(mappingTargetProblems({ key: 'CN=a', value: 'org-acme-admin' }, groups, none).map((p) => p.tone)).toEqual(['warning', 'error']);
    });

    it('judges nothing without the group list', () => {
        expect(mappingTargetProblems({ key: 'CN=a', value: 'anything' }, null, none)).toEqual([]);
    });
});

describe('LDAP mappings: DNs and storage', () => {
    it.each([
        'CN=PKI Operators,OU=Groups,DC=example,DC=com',
        'cn=admins,dc=example,dc=com',
        'CN=Smith\\, John,OU=People,DC=example,DC=com',
        'CN="Smith, John",DC=example',
        'CN=a+UID=b,DC=example',
        '2.5.4.3=Admins,DC=example',
    ])('accepts the DN %s', (dn) => expect(validateLdapDn(dn)).toBeNull());

    it.each([
        'Admins',
        'CN=Admins,',
        'CN=,DC=example',
        '=Admins,DC=example',
        'CN=Admins,DC=example\\',
        'CN="Admins,DC=example',
        'C N=Admins',
    ])('refuses the DN %s', (dn) => expect(validateLdapDn(dn)).not.toBeNull());

    it('compares DNs ignoring case and surrounding space, as sync matches them', () => {
        expect(normalizeDnKey(' cn=Admins,DC=x ')).toBe(normalizeDnKey('CN=admins,dc=X'));
    });

    it('round-trips the stored JSON object, in order', () => {
        const stored = '{"CN=Ops,DC=x":"space-acme-user","CN=Beta,DC=x":"space-beta-operator"}';
        const { rows, notices } = mappingRowsFromStored(stored);
        expect(notices).toEqual([]);
        expect(rows).toEqual([{ key: 'CN=Ops,DC=x', value: 'space-acme-user' }, { key: 'CN=Beta,DC=x', value: 'space-beta-operator' }]);
        expect(mappingRowsToJson(rows)).toBe(stored);
    });

    it('reads blank as no mappings, and reports text that is not a JSON object or a non-text target', () => {
        expect(mappingRowsFromStored('')).toEqual({ rows: [], notices: [] });
        expect(mappingRowsFromStored(null)).toEqual({ rows: [], notices: [] });
        expect(mappingRowsFromStored('{nope').notices).toHaveLength(1);
        expect(mappingRowsFromStored('["CN=x"]').notices).toHaveLength(1);
        expect(mappingRowsFromStored('{"CN=x":null,"CN=y":"g"}')).toEqual({ rows: [{ key: 'CN=y', value: 'g' }], notices: [expect.stringMatching(/CN=x/)] });
    });
});
