import { describe, expect, it } from 'vitest';
import { mfaHeader, runWithOneStepUp, STEP_UP_BATCH, STEP_UP_CANCELLED } from '@shared-auth/api/stepUpBatch';

const items = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `id-${i}` }));

describe('one step-up prompt for a bulk action', () => {
    it('prompts once, names every item, and sends the token with each call', async () => {
        const prompts: Array<{ op: string; target: unknown }> = [];
        const sent: string[] = [];
        const result = await runWithOneStepUp(items(3), (i) => i.id,
            async (op, target) => { prompts.push({ op, target }); return 'tok'; },
            'approve-request',
            async (item, headers) => { sent.push(`${item.id}:${headers['X-MFA-Token']}`); });

        expect(prompts).toEqual([{ op: 'approve-request', target: ['id-0', 'id-1', 'id-2'] }]);
        expect(sent).toEqual(['id-0:tok', 'id-1:tok', 'id-2:tok']);
        expect(result).toEqual({ ok: 3, failures: [], cancelled: false });
    });

    it('keeps going when one item fails, and reports why', async () => {
        const result = await runWithOneStepUp(items(3), (i) => i.id, async () => 'tok', 'reject-request',
            async (item) => { if (item.id === 'id-1') throw new Error('You cannot approve your own request'); });

        expect(result).toEqual({ ok: 2, failures: ['You cannot approve your own request'], cancelled: false });
    });

    it('does nothing when the prompt is dismissed', async () => {
        let calls = 0;
        const result = await runWithOneStepUp(items(2), (i) => i.id,
            async () => { throw new Error(STEP_UP_CANCELLED); }, 'revoke-ssh-cert', async () => { calls++; });

        expect(calls).toBe(0);
        expect(result).toEqual({ ok: 0, failures: [], cancelled: true });
    });

    it('prompts again for each further group the server limit allows', async () => {
        const sizes: number[] = [];
        const result = await runWithOneStepUp(items(STEP_UP_BATCH + 5), (i) => i.id,
            async (_op, target) => { sizes.push((target as string[]).length); return `tok-${sizes.length}`; },
            'manage-trust-anchor', async () => {});

        expect(sizes).toEqual([STEP_UP_BATCH, 5]);
        expect(result.ok).toBe(STEP_UP_BATCH + 5);
    });

    it('stops at a dismissed later prompt and keeps what was done', async () => {
        let prompts = 0;
        const result = await runWithOneStepUp(items(STEP_UP_BATCH + 5), (i) => i.id,
            async () => { if (++prompts === 2) throw new Error(STEP_UP_CANCELLED); return 'tok'; },
            'manage-trust-anchor', async () => {});

        expect(result).toEqual({ ok: STEP_UP_BATCH, failures: [], cancelled: true });
    });

    it('passes on a failure of the prompt itself', async () => {
        await expect(runWithOneStepUp(items(1), (i) => i.id,
            async () => { throw new Error('Too many attempts'); }, 'approve-request', async () => {}))
            .rejects.toThrow('Too many attempts');
    });

    it('builds the header a held token is sent in', () => {
        expect(mfaHeader('abc')).toEqual({ 'X-MFA-Token': 'abc' });
    });
});
