/** Generic Markdown rendering helpers shared by the response renderers. */

export type Cell = string | number | boolean | null | undefined;

/**
 * Render a Unix timestamp as an ISO date.
 *
 * SecurityTrails mixes units within a single record — `whois.createdDate` arrives in
 * milliseconds while `first_seen` on the same object arrives in seconds — so the unit is
 * inferred rather than assumed: if interpreting the value as seconds lands implausibly far in
 * the future, it must already be milliseconds.
 */
export function epochToDate(value: unknown): string | undefined {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return undefined;
    const asSeconds = new Date(value * 1000);
    const millis = asSeconds.getUTCFullYear() > 2200 ? value : value * 1000;
    const date = new Date(millis);
    if (Number.isNaN(date.getTime())) return undefined;
    return date.toISOString().slice(0, 10);
}

/** Normalise any date-ish field: passes ISO strings through, converts epochs. */
export function asDate(value: unknown): string | undefined {
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) return undefined;
        // "1995-08-14T00:00:00Z" carries no useful time component.
        return trimmed.length > 10 && trimmed.includes('T') ? trimmed.slice(0, 10) : trimmed;
    }
    return epochToDate(value);
}

/** Render a value for use inside a table cell, escaping pipes and newlines. */
export function cell(value: Cell): string {
    if (value === null || value === undefined || value === '') return '—';
    return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Join a list of scalars, collapsing empties to a dash. */
export function joinList(values: unknown, separator = ', '): string {
    if (!Array.isArray(values) || values.length === 0) return '—';
    return values.map(value => cell(value as Cell)).join(separator);
}

export function table(headers: string[], rows: Cell[][]): string {
    if (rows.length === 0) return '';
    const head = `| ${headers.join(' | ')} |`;
    const rule = `| ${headers.map(() => '---').join(' | ')} |`;
    const body = rows.map(row => `| ${row.map(cell).join(' | ')} |`).join('\n');
    return `${head}\n${rule}\n${body}`;
}

/** A `**Key:** value` list, skipping entries with no value. */
export function fields(pairs: [string, Cell][]): string {
    const present = pairs.filter(([, value]) => value !== null && value !== undefined && value !== '');
    if (present.length === 0) return '';
    return present.map(([key, value]) => `**${key}:** ${cell(value)}`).join('\n');
}

export function bullets(items: Cell[]): string {
    if (items.length === 0) return '';
    return items.map(item => `- ${cell(item)}`).join('\n');
}

/** Assemble sections, dropping empty ones and separating with a blank line. */
export function compose(...parts: (string | undefined | false)[]): string {
    return parts.filter((part): part is string => Boolean(part) && String(part).trim() !== '').join('\n\n');
}

export interface PageInfo {
    page?: number;
    totalPages?: number;
    totalCount?: number;
    /** Name of the tool to call again, for the "next page" hint. */
    tool?: string;
}

/** A consistent pagination footer so the model knows whether more data exists. */
export function pageFooter(info: PageInfo): string {
    const { page, totalPages, totalCount, tool } = info;
    const parts: string[] = [];
    if (typeof totalCount === 'number') parts.push(`${totalCount} record(s) total`);
    if (typeof page === 'number' && typeof totalPages === 'number' && totalPages > 0) {
        parts.push(`page ${page} of ${totalPages}`);
    }
    if (parts.length === 0) return '';
    const hasMore = typeof page === 'number' && typeof totalPages === 'number' && page < totalPages;
    const hint = hasMore
        ? ` — more available; call ${tool ?? 'this tool'} again with \`page: ${page + 1}\` (costs one further API query).`
        : '';
    return `_${parts.join(', ')}${hint || '.'}_`;
}
