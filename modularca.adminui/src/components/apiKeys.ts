/** One named API key of an integration, as `GET /api/v1/admin/api-keys` returns it. The key itself is never returned. */
export interface ApiKeyRow {
    id: string;
    integration: string;
    name: string;
    /** The key's last four characters. */
    hint: string;
    /** A space id, `instance`, or null for whatever the integration is allowed. */
    spaceScope: string | null;
    status: 'active' | 'revoked' | 'expired';
    createdAt: string;
    createdBy: string;
    expiresAt: string | null;
    revokedAt: string | null;
    revokedBy: string | null;
    lastUsedAt: string | null;
}

export interface SpaceOption {
    id: string;
    name: string;
}

/** The value a scope select sends for "the integration's own scope". */
export const INTEGRATION_SCOPE = '';

/** The value the server takes for the instance's own CAs. */
export const INSTANCE_SCOPE = 'instance';

/** The badge for a key's status. A revoked or expired key does not work; only the wording differs. */
export function apiKeyBadge(key: Pick<ApiKeyRow, 'status'>): { status: 'active' | 'revoked' | 'expired'; label: string } {
    if (key.status === 'revoked') return { status: 'revoked', label: 'Revoked' };
    if (key.status === 'expired') return { status: 'expired', label: 'Expired' };
    return { status: 'active', label: 'Active' };
}

/** How a key is shown when the key itself cannot be: its prefix and its last four characters. */
export function apiKeyHint(hint: string): string {
    return `mca_…${hint}`;
}

/** A key's scope in words. A space that is no longer listed is shown by its id. */
export function apiKeyScopeLabel(spaceScope: string | null, spaces: SpaceOption[]): string {
    if (!spaceScope) return "The integration's scope";
    if (spaceScope.toLowerCase() === INSTANCE_SCOPE) return 'Instance CAs only';
    const space = spaces.find((s) => s.id.toLowerCase() === spaceScope.toLowerCase());
    return space ? `Space: ${space.name}` : `Space ${spaceScope}`;
}

/**
 * What the create form sends, or the reason it cannot be sent. An expiry left empty is a key that
 * does not expire.
 */
export function apiKeyRequest(integration: string, name: string, scope: string, expiresInDays: string):
    { body: { integration: string; name: string; spaceScope?: string; expiresInDays?: number } } | { problem: string } {
    const trimmed = name.trim();
    if (!trimmed) return { problem: 'Give the key a name, usually the client that will hold it.' };
    if (trimmed.length > 100) return { problem: 'A name is at most 100 characters.' };

    const body: { integration: string; name: string; spaceScope?: string; expiresInDays?: number } = { integration, name: trimmed };
    if (scope !== INTEGRATION_SCOPE) body.spaceScope = scope;

    const days = expiresInDays.trim();
    if (days) {
        if (!/^\d+$/.test(days) || Number(days) < 1 || Number(days) > 3650)
            return { problem: 'Expiry is a whole number of days from 1 to 3650, or empty for a key that does not expire.' };
        body.expiresInDays = Number(days);
    }
    return { body };
}
