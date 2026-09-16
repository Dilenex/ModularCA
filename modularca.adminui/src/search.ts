/**
 * Page matching for the global search. Pure, so the test project covers it.
 *
 * A page matches when every word of the query appears in its name, its keywords or its
 * section; results are ordered by how early the first query word appears in the name, then by
 * whether the name starts with the query, so "cert" lists "Certificates" before "Trust
 * Anchors" (whose keywords mention certificates).
 */
export interface SearchablePage {
    name: string;
    path: string;
    section: string;
    keywords?: string[];
}

export interface PageHit extends SearchablePage {
    score: number;
}

export function searchPages<T extends SearchablePage>(pages: T[], query: string, limit = 8): Array<T & PageHit> {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return [];
    const hits: Array<T & PageHit> = [];
    for (const page of pages) {
        const name = page.name.toLowerCase();
        const haystack = [name, page.section.toLowerCase(), ...(page.keywords ?? []).map(k => k.toLowerCase())].join(' ');
        if (!words.every(w => haystack.includes(w))) continue;
        const firstInName = name.indexOf(words[0]);
        // Lower is better: a name hit beats a keyword-only hit, and an earlier name hit beats a later one.
        const score = firstInName === -1 ? 1000 : firstInName === 0 ? 0 : 1 + firstInName;
        hits.push({ ...page, score });
    }
    return hits.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name)).slice(0, limit);
}
