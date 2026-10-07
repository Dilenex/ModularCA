import { useState, useMemo } from 'react';
import EndpointCard from '../components/EndpointCard';
import type { Endpoint } from '../components/EndpointCard';

let importedEndpoints: Endpoint[] = [];
try {
    const mod = await import('../data/endpoints');
    importedEndpoints = mod.endpoints ?? [];
} catch {
    // Data file not yet created; use empty array
}

export default function ApiReference() {
    const [search, setSearch] = useState('');
    const [activeCategory, setActiveCategory] = useState<string | null>(null);

    const endpoints: Endpoint[] = importedEndpoints;

    const categories = useMemo(() => {
        const set = new Set<string>();
        for (const ep of endpoints) {
            set.add(ep.category);
        }
        return Array.from(set).sort();
    }, [endpoints]);

    const filtered = useMemo(() => {
        const query = search.toLowerCase().trim();
        return endpoints.filter((ep) => {
            const matchesCategory = !activeCategory || ep.category === activeCategory;
            const matchesSearch =
                !query ||
                ep.path.toLowerCase().includes(query) ||
                ep.summary.toLowerCase().includes(query) ||
                ep.category.toLowerCase().includes(query);
            return matchesCategory && matchesSearch;
        });
    }, [endpoints, search, activeCategory]);

    const grouped = useMemo(() => {
        const map = new Map<string, Endpoint[]>();
        for (const ep of filtered) {
            const list = map.get(ep.category) ?? [];
            list.push(ep);
            map.set(ep.category, list);
        }
        return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
    }, [filtered]);

    return (
        <div className="max-w-4xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-semibold text-ink mb-2">
                    API Reference
                </h1>
                <p className="text-ink-muted">
                    Complete REST API documentation for all ModularCA endpoints.
                </p>
            </div>

            {/* Search */}
            <div className="mb-4">
                <input
                    type="text"
                    placeholder="Search endpoints by path, summary, or category..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="w-full px-4 py-2 text-sm bg-raised border border-line-strong rounded-lg text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                />
            </div>

            {/* Category filter pills */}
            {categories.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-6">
                    <button
                        type="button"
                        onClick={() => setActiveCategory(null)}
                        className={`px-3 py-1 text-sm rounded-full border transition-colors cursor-pointer ${
                            activeCategory === null
                                ? 'bg-accent text-on-accent border-accent'
                                : 'bg-raised text-ink border-line-strong hover:border-accent'
                        }`}
                    >
                        All
                    </button>
                    {categories.map((cat) => (
                        <button
                            key={cat}
                            type="button"
                            onClick={() => setActiveCategory(cat === activeCategory ? null : cat)}
                            className={`px-3 py-1 text-sm rounded-full border transition-colors cursor-pointer ${
                                activeCategory === cat
                                    ? 'bg-accent text-on-accent border-accent'
                                    : 'bg-raised text-ink border-line-strong hover:border-accent'
                            }`}
                        >
                            {cat}
                        </button>
                    ))}
                </div>
            )}

            {/* Count */}
            <p className="text-sm text-ink-muted mb-6">
                Showing {filtered.length} of {endpoints.length} endpoints
            </p>

            {/* Grouped endpoint list */}
            {grouped.length === 0 ? (
                <div className="text-center py-12 text-ink-muted">
                    {endpoints.length === 0
                        ? 'No endpoints loaded. The endpoint data file has not been created yet.'
                        : 'No endpoints match your search.'}
                </div>
            ) : (
                <div className="space-y-8">
                    {grouped.map(([category, eps]) => (
                        <section key={category}>
                            <h2 className="text-xl font-semibold text-ink mb-4">
                                {category}
                            </h2>
                            <div className="space-y-2">
                                {eps.map((ep, idx) => (
                                    <EndpointCard key={`${ep.method}-${ep.path}-${idx}`} endpoint={ep} />
                                ))}
                            </div>
                        </section>
                    ))}
                </div>
            )}
        </div>
    );
}
