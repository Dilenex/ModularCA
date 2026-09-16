import type { ApiEndpoint } from '../types';
import { acme } from './acme';
import { est } from './est';
import { scep } from './scep';
import { cmp } from './cmp';
import { msae } from './msae';

export const protocols: ApiEndpoint[] = [
    ...acme,
    ...est,
    ...scep,
    ...cmp,
    ...msae,
];
