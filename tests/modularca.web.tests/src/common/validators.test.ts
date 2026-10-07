import { describe, expect, it } from 'vitest';
import {
    formatIp, looksLikeHostname, parseIp, validateAbsoluteFilePath, validateEmail, validateIpOrCidr, validateOid,
    validateOrigin, validatePathPrefix, validatePositiveInteger, validateRegex,
} from '@shared/validators';
import { looksLikeHostname as fromHostnameModule } from '@shared/hostname';

const ok = (v: string | null) => expect(v).toBeNull();
const bad = (v: string | null) => expect(v).toEqual(expect.any(String));

describe('validateIpOrCidr', () => {
    it('accepts IPv4 and IPv6 addresses and ranges', () => {
        for (const v of ['10.0.0.1', '10.0.0.0/8', '0.0.0.0/0', '192.168.1.0/24', '::1', '::1/128', '::/0', '2001:db8::/32', 'fe80::1', '::ffff:10.0.0.1', '1:2:3:4:5:6:7:8']) {
            ok(validateIpOrCidr(v));
        }
    });

    it('refuses malformed addresses and prefixes', () => {
        for (const v of ['', '10.0.0', '10.0.0.256', '010.0.0.1', '10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/', '10.0.0.0/8/8', '::1/129', '1::2::3', 'fe80::1%eth0', 'example.com', '*', '1:2:3:4:5:6:7:8:9']) {
            bad(validateIpOrCidr(v));
        }
    });

    it('tolerates host bits unless the network address is required, and then names it', () => {
        ok(validateIpOrCidr('10.0.0.1/8'));
        expect(validateIpOrCidr('10.0.0.1/8', { requireNetworkAddress: true })).toContain('10.0.0.0/8');
        expect(validateIpOrCidr('2001:db8::1/32', { requireNetworkAddress: true })).toContain('2001:db8::/32');
        ok(validateIpOrCidr('10.0.0.1', { requireNetworkAddress: true }));
        ok(validateIpOrCidr('172.16.0.0/12', { requireNetworkAddress: true }));
    });

    it('round-trips addresses through parse and format', () => {
        expect(formatIp(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')!)).toBe('2001:db8::1');
        expect(formatIp(parseIp('10.1.2.3')!)).toBe('10.1.2.3');
    });
});

describe('validateEmail', () => {
    it('accepts bare addresses and refuses the rest', () => {
        ok(validateEmail('ops@example.com'));
        for (const v of ['ops', 'ops@example', 'Ops <ops@example.com>', 'a b@example.com', '']) bad(validateEmail(v));
    });
});

describe('validateOrigin', () => {
    it('accepts https origins with an optional port', () => {
        ok(validateOrigin('https://app.example.com'));
        ok(validateOrigin('https://app.example.com:8443'));
    });

    it('accepts plain http only for localhost', () => {
        ok(validateOrigin('http://localhost:5173'));
        ok(validateOrigin('http://127.0.0.1:3000'));
        ok(validateOrigin('http://[::1]:3000'));
        bad(validateOrigin('http://app.example.com'));
        bad(validateOrigin('http://localhost', { allowHttpLocalhost: false }));
    });

    it('refuses paths, trailing slashes, wildcards and other schemes', () => {
        expect(validateOrigin('https://app.example.com/')).toContain('trailing');
        for (const v of ['https://app.example.com/path', 'https://app.example.com?x=1', '*', 'https://*.example.com', 'ftp://example.com', 'app.example.com', 'https://user@app.example.com']) {
            bad(validateOrigin(v));
        }
    });
});

describe('validatePathPrefix', () => {
    it('needs a leading slash and nothing a prefix match would never see', () => {
        ok(validatePathPrefix('/health'));
        ok(validatePathPrefix('/api/v1/public/ca'));
        for (const v of ['health', '/api/*', '/a b', '/x?y=1', 'https://h/x']) bad(validatePathPrefix(v));
    });
});

describe('validateAbsoluteFilePath', () => {
    it('accepts Linux, Windows drive and UNC paths only', () => {
        for (const v of ['/etc/modularca/ca.pem', 'C:\\ModularCA\\ca.pem', 'd:/certs/ca.pem', '\\\\server\\share\\ca.pem']) ok(validateAbsoluteFilePath(v));
        for (const v of ['ca.pem', './ca.pem', 'certs\\ca.pem', 'C:ca.pem']) bad(validateAbsoluteFilePath(v));
    });
});

describe('validateOid', () => {
    it('checks dotted OIDs and the X.660 arc limits', () => {
        for (const v of ['1.3.6.1.4.1.311.20.2.2', '2.5.29.32.0', '2.999.1', '0.39']) ok(validateOid(v));
        for (const v of ['1', '3.1', '1.40', '1.3.06', '1..3', 'a.b', '']) bad(validateOid(v));
    });
});

describe('validateRegex', () => {
    it('compiles the pattern and mentions the .NET dialect when it fails', () => {
        ok(validateRegex('^[a-z_][a-z0-9_-]{0,31}$'));
        expect(validateRegex('^(admin')).toContain('.NET');
        bad(validateRegex(''));
    });
});

describe('validatePositiveInteger', () => {
    it('accepts whole numbers from 1 up to the limit', () => {
        ok(validatePositiveInteger('1'));
        ok(validatePositiveInteger('3650', 3650));
        for (const v of ['0', '-1', '1.5', 'x', '', '3651']) bad(validatePositiveInteger(v, 3650));
        bad(validatePositiveInteger('2147483648'));
    });
});

describe('looksLikeHostname', () => {
    it('is the same function from its old home', () => {
        expect(fromHostnameModule).toBe(looksLikeHostname);
        expect(looksLikeHostname('*.example.com')).toBe(true);
        expect(looksLikeHostname('John Smith')).toBe(false);
    });
});
