import { describe, expect, it } from 'vitest';
import { apiKeyBadge, apiKeyHint, apiKeyRequest, apiKeyScopeLabel, INSTANCE_SCOPE, INTEGRATION_SCOPE } from '@adminui/components/apiKeys';

describe('how a named API key is shown', () => {
    it('is identified by its prefix and last four characters, never by itself', () => {
        expect(apiKeyHint('x7Qa')).toBe('mca_…x7Qa');
    });

    it('says whether it works', () => {
        expect(apiKeyBadge({ status: 'active' })).toEqual({ status: 'active', label: 'Active' });
        expect(apiKeyBadge({ status: 'revoked' }).label).toBe('Revoked');
        expect(apiKeyBadge({ status: 'expired' }).label).toBe('Expired');
    });

    it('names its scope in words', () => {
        const spaces = [{ id: '3F2504E0-4F89-11D3-9A0C-0305E82C3301', name: 'Customer A' }];
        expect(apiKeyScopeLabel(null, spaces)).toBe("The integration's scope");
        expect(apiKeyScopeLabel('instance', spaces)).toBe('Instance CAs only');
        expect(apiKeyScopeLabel('3f2504e0-4f89-11d3-9a0c-0305e82c3301', spaces)).toBe('Space: Customer A');
        // A space that has since gone is still named by what the key holds.
        expect(apiKeyScopeLabel('11111111-1111-1111-1111-111111111111', spaces)).toBe('Space 11111111-1111-1111-1111-111111111111');
    });
});

describe('what the create form sends', () => {
    it('sends the name alone for a key with the integration\'s scope and no expiry', () => {
        expect(apiKeyRequest('integration', '  terraform-prod ', INTEGRATION_SCOPE, '')).toEqual({
            body: { integration: 'integration', name: 'terraform-prod' },
        });
    });

    it('sends a scope and an expiry when they are chosen', () => {
        expect(apiKeyRequest('cert-manager', 'cluster-a', INSTANCE_SCOPE, ' 90 ')).toEqual({
            body: { integration: 'cert-manager', name: 'cluster-a', spaceScope: 'instance', expiresInDays: 90 },
        });
    });

    it('asks for a name', () => {
        expect(apiKeyRequest('integration', '   ', INTEGRATION_SCOPE, '')).toHaveProperty('problem');
        expect(apiKeyRequest('integration', 'n'.repeat(101), INTEGRATION_SCOPE, '')).toHaveProperty('problem');
    });

    it('refuses an expiry that is not a whole number of days in range', () => {
        for (const days of ['0', '3651', '1.5', '-3', 'soon'])
            expect(apiKeyRequest('integration', 'k', INTEGRATION_SCOPE, days)).toHaveProperty('problem');
        expect(apiKeyRequest('integration', 'k', INTEGRATION_SCOPE, '3650')).toHaveProperty('body');
    });
});
