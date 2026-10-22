import { describe, expect, it } from 'vitest';
import { AUTO_REFRESH_SECONDS, autoRefreshDue, autoRefreshLabel } from '@shared/tableRefresh';

describe('when a table that refreshes itself reloads', () => {
    const watching = { enabled: true, pageHidden: false, selectedCount: 0, drawerOpen: false };

    it('reloads while it is switched on and being looked at', () => {
        expect(autoRefreshDue(watching)).toBe(true);
    });

    it('does not reload when it is switched off', () => {
        expect(autoRefreshDue({ ...watching, enabled: false })).toBe(false);
    });

    it('holds off while reloading would pull something out from under the reader', () => {
        // Ticked rows would lose their ticks; an open drawer would lose its row.
        expect(autoRefreshDue({ ...watching, selectedCount: 2 })).toBe(false);
        expect(autoRefreshDue({ ...watching, drawerOpen: true })).toBe(false);
    });

    it('does not reload a page nobody is looking at', () => {
        expect(autoRefreshDue({ ...watching, pageHidden: true })).toBe(false);
    });

    it('says how often', () => {
        expect(autoRefreshLabel(AUTO_REFRESH_SECONDS)).toBe('Auto 30s');
        expect(autoRefreshLabel(120)).toBe('Auto 2m');
    });
});
