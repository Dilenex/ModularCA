import { describe, expect, it } from 'vitest';
import type { ServerKeyOption, ServerKeyRefusal } from '@shared/generated';
import {
    chooseAlgorithm, findOption, groupRefusals, keyLabel, offeredAlgorithms, offeredSizes,
    requestKeySize, settleKeyChoice,
} from '@adminui/pages/keyOptions';

/** The key pickers of the certificate request form, fed by the server's `key-options` answer. */

const option = (algorithm: string, keySize: string | null, signatureAlgorithm = 'sig'): ServerKeyOption =>
    ({ algorithm, keySize, signatureAlgorithm });

const offered: ServerKeyOption[] = [
    option('RSA', '3072', 'SHA256withRSAandMGF1'),
    option('RSA', '4096', 'SHA256withRSAandMGF1'),
    option('ECDSA', 'P-384', 'SHA384withECDSA'),
    option('Ed25519', null, 'Ed25519'),
];

describe('the pickers', () => {
    it('list each offered algorithm once, in the order the server gave', () => {
        expect(offeredAlgorithms(offered)).toEqual(['RSA', 'ECDSA', 'Ed25519']);
        expect(offeredAlgorithms([])).toEqual([]);
    });

    it('list only the sizes offered for the algorithm', () => {
        expect(offeredSizes(offered, 'RSA')).toEqual(['3072', '4096']);
        expect(offeredSizes(offered, 'ECDSA')).toEqual(['P-384']);
    });

    it('show no size picker for an algorithm without sizes', () => {
        expect(offeredSizes(offered, 'Ed25519')).toEqual([]);
        expect(offeredSizes(offered, 'ML-DSA-65')).toEqual([]);
    });

    it('move to the first offered key of a newly picked algorithm', () => {
        expect(chooseAlgorithm(offered, 'ECDSA')).toEqual({ algorithm: 'ECDSA', keySize: 'P-384' });
        expect(chooseAlgorithm(offered, 'Ed25519')).toEqual({ algorithm: 'Ed25519', keySize: null });
        expect(chooseAlgorithm(offered, 'Ed448')).toBeNull();
    });
});

describe('the choice when the offered keys change', () => {
    it('is kept while it is still offered', () => {
        expect(settleKeyChoice(offered, { algorithm: 'RSA', keySize: '4096' })).toEqual({ algorithm: 'RSA', keySize: '4096' });
        expect(settleKeyChoice(offered, { algorithm: 'Ed25519', keySize: null })).toEqual({ algorithm: 'Ed25519', keySize: null });
    });

    it('moves to the first offered size of the same algorithm when its size is gone', () => {
        expect(settleKeyChoice(offered, { algorithm: 'RSA', keySize: '2048' })).toEqual({ algorithm: 'RSA', keySize: '3072' });
    });

    it('moves to the first offered key when its algorithm is gone, or nothing was chosen', () => {
        expect(settleKeyChoice(offered, { algorithm: 'Ed448', keySize: null })).toEqual({ algorithm: 'RSA', keySize: '3072' });
        expect(settleKeyChoice(offered, null)).toEqual({ algorithm: 'RSA', keySize: '3072' });
    });

    it('is nothing when no key is offered', () => {
        expect(settleKeyChoice([], { algorithm: 'RSA', keySize: '2048' })).toBeNull();
    });

    it('reads a missing size from the server as no size', () => {
        const fromServer = [{ algorithm: 'Ed448', signatureAlgorithm: 'Ed448' }] as ServerKeyOption[];
        expect(settleKeyChoice(fromServer, null)).toEqual({ algorithm: 'Ed448', keySize: null });
        expect(findOption(fromServer, { algorithm: 'Ed448', keySize: null })).toBe(fromServer[0]);
    });
});

describe('the chosen key', () => {
    it('is found only when it is offered', () => {
        expect(findOption(offered, { algorithm: 'ECDSA', keySize: 'P-384' })?.signatureAlgorithm).toBe('SHA384withECDSA');
        expect(findOption(offered, { algorithm: 'ECDSA', keySize: 'P-256' })).toBeUndefined();
        expect(findOption(offered, null)).toBeUndefined();
    });

    it('is sent with the algorithm name as the size where there is none', () => {
        expect(requestKeySize({ algorithm: 'RSA', keySize: '4096' })).toBe('4096');
        expect(requestKeySize({ algorithm: 'ML-DSA-65', keySize: null })).toBe('ML-DSA-65');
    });

    it('is named by algorithm and size', () => {
        expect(keyLabel({ algorithm: 'ECDSA', keySize: 'P-256' })).toBe('ECDSA P-256');
        expect(keyLabel({ algorithm: 'Ed25519', keySize: null })).toBe('Ed25519');
    });
});

describe('the keys not offered', () => {
    it('are grouped under the reason, in the order the reasons first appear', () => {
        const refused: ServerKeyRefusal[] = [
            { algorithm: 'RSA', keySize: '2048', reason: 'Key size "2048" is not permitted.' },
            { algorithm: 'Ed448', keySize: null, reason: 'Key algorithm "Ed448" is not permitted.' },
            { algorithm: 'RSA', keySize: '8192', reason: 'Key size "2048" is not permitted.' },
        ];
        expect(groupRefusals(refused)).toEqual([
            { reason: 'Key size "2048" is not permitted.', keys: ['RSA 2048', 'RSA 8192'] },
            { reason: 'Key algorithm "Ed448" is not permitted.', keys: ['Ed448'] },
        ]);
        expect(groupRefusals([])).toEqual([]);
    });
});
