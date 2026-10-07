import { describe, expect, it } from 'vitest';
import {
    type CheckboxOption, ceilingEmptyOnly, ceilingListOut, ceilingModeFromList, ceilingModeOf, flattenGroups, groupState, setGroup, toggleValue, unknownValues,
} from '@shared/components/checkboxListModel';

const opts = (...values: string[]): CheckboxOption[] => values.map((value) => ({ value, label: value }));

describe('CheckboxList model', () => {
    it('appends a ticked value and keeps the stored order', () => {
        expect(toggleValue(['b', 'a'], 'c', true)).toEqual(['b', 'a', 'c']);
        expect(toggleValue(['b', 'a'], 'a', true)).toEqual(['b', 'a']);
        expect(toggleValue(['b', 'a', 'c'], 'a', false)).toEqual(['b', 'c']);
    });

    it('reports and sets a group over its enabled options only', () => {
        const group: CheckboxOption[] = [...opts('a', 'b'), { value: 'c', label: 'c', disabled: true }];
        expect(groupState([], group)).toBe('none');
        expect(groupState(['a'], group)).toBe('some');
        expect(groupState(['a', 'b'], group)).toBe('all');
        expect(setGroup(['x'], group, true)).toEqual(['x', 'a', 'b']);
        expect(setGroup(['x', 'a', 'b', 'c'], group, false)).toEqual(['x', 'c']);
    });

    it('lists stored values no option offers, once each', () => {
        expect(unknownValues(['a', 'z', 'z', 'b'], opts('a', 'b'))).toEqual(['z']);
        expect(flattenGroups([{ id: 'g', label: 'G', options: opts('a') }, { id: 'h', label: 'H', options: opts('b') }]).map((o) => o.value)).toEqual(['a', 'b']);
    });

    it('treats an empty ceiling as Any unless Only these was chosen', () => {
        expect(ceilingModeOf([], false)).toBe('any');
        expect(ceilingModeOf([], true)).toBe('only');
        expect(ceilingModeOf(['a'], false)).toBe('only');
        expect(ceilingEmptyOnly('only', [])).toBe(true);
        expect(ceilingEmptyOnly('only', ['a'])).toBe(false);
        expect(ceilingEmptyOnly('any', [])).toBe(false);
    });

    it('loads an empty ceiling as Any and saves Any as empty', () => {
        expect(ceilingModeFromList([])).toBe('any');
        expect(ceilingModeFromList(['a'])).toBe('only');
        expect(ceilingListOut('any', ['a'])).toEqual([]);
        expect(ceilingListOut('only', ['a'])).toEqual(['a']);
    });
});
