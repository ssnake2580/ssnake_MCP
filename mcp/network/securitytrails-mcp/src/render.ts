/**
 * Markdown renderers for each SecurityTrails response shape.
 *
 * Every renderer returns `undefined` when the payload does not match the shape it expects, and
 * the caller then falls back to raw JSON. Silently dropping data would be worse than a verbose
 * response, so an unrecognised payload is never rendered as an empty section.
 */

import { asDate, bullets, compose, fields, joinList, pageFooter, table, type Cell } from './markdown.js';

export type Renderer = (data: unknown) => string | undefined;

// ---- narrowing helpers ------------------------------------------------------

function obj(value: unknown): Record<string, unknown> | undefined {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
}

function arr(value: unknown): unknown[] | undefined {
    return Array.isArray(value) ? value : undefined;
}

function str(value: unknown): string | undefined {
    return typeof value === 'string' && value !== '' ? value : undefined;
}

function num(value: unknown): number | undefined {
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/** First array element, or the scalar itself — SecurityTrails mixes both for the same field. */
function firstOf(value: unknown): Cell {
    const list = arr(value);
    if (list) return list.length > 0 ? (list[0] as Cell) : undefined;
    return value as Cell;
}

/** The salient scalar inside a DNS value object, whatever record type it belongs to. */
function primaryValue(value: unknown): string | undefined {
    const record = obj(value);
    if (!record) return typeof value === 'string' ? value : undefined;
    for (const key of ['ip', 'ipv6', 'nameserver', 'hostname', 'email', 'value']) {
        const found = str(record[key]);
        if (found) return found;
    }
    return undefined;
}

/** The organisation attributed to a DNS value, across the differing key names. */
function valueOrganization(value: unknown): string | undefined {
    const record = obj(value);
    if (!record) return undefined;
    for (const key of ['ip_organization', 'ipv6_organization', 'nameserver_organization', 'hostname_organization']) {
        const found = str(record[key]);
        if (found) return found;
    }
    return undefined;
}

function meta(data: Record<string, unknown>): { page?: number; totalPages?: number } {
    const block = obj(data.meta);
    return { page: num(block?.page), totalPages: num(block?.total_pages) ?? num(data.pages) };
}

// ---- account ----------------------------------------------------------------

export const renderPing: Renderer = data => {
    const record = obj(data);
    if (!record) return undefined;
    return record.success === true
        ? '**API key valid.** SecurityTrails accepted the configured key.'
        : '**API key check failed.** SecurityTrails did not confirm the key.';
};

export const renderUsage: Renderer = data => {
    const record = obj(data);
    if (!record) return undefined;
    const allowed = num(record.allowed_monthly_usage);
    const used = num(record.current_monthly_usage);
    if (allowed === undefined || used === undefined) return undefined;
    return compose(
        '## API quota',
        fields([
            ['Used this month', used.toLocaleString('en-US')],
            ['Monthly allowance', allowed.toLocaleString('en-US')],
            ['Remaining', num(record.remaining)?.toLocaleString('en-US')],
            ['Consumed', `${String(record.percent_used)}%`]
        ])
    );
};

// ---- domain -----------------------------------------------------------------

/** Human labels for the DNS record blocks inside `current_dns`. */
const DNS_BLOCKS: [key: string, label: string][] = [
    ['a', 'A'],
    ['aaaa', 'AAAA'],
    ['mx', 'MX'],
    ['ns', 'NS'],
    ['soa', 'SOA'],
    ['txt', 'TXT']
];

export const renderDomainDetails: Renderer = data => {
    const record = obj(data);
    const dns = obj(record?.current_dns);
    if (!record || !dns) return undefined;

    const host = str(record.hostname) ?? str(record.apex_domain) ?? 'domain';
    const sections = DNS_BLOCKS.map(([key, label]) => {
        const block = obj(dns[key]);
        const values = arr(block?.values);
        if (!values || values.length === 0) return '';
        const seen = asDate(block?.first_seen);
        const rows: Cell[][] = values.map(value => {
            const entry = obj(value);
            const priority = num(entry?.priority);
            return [
                priority === undefined ? primaryValue(value) : `${priority} ${primaryValue(value) ?? ''}`.trim(),
                valueOrganization(value),
                num(entry?.ttl)
            ];
        });
        const hasTtl = rows.some(row => row[2] !== undefined);
        const trimmed: Cell[][] = hasTtl ? rows : rows.map(row => row.slice(0, 2));
        const headers = hasTtl ? ['Value', 'Organization', 'TTL'] : ['Value', 'Organization'];
        return compose(`### ${label}${seen ? ` _(first seen ${seen})_` : ''}`, table(headers, trimmed));
    });

    return compose(
        `## ${host}`,
        fields([
            ['Apex domain', str(record.apex_domain)],
            ['Subdomains recorded', num(record.subdomain_count)],
            ['Alexa rank', num(record.alexa_rank)]
        ]),
        ...sections
    );
};

export const renderSubdomains: Renderer = data => {
    const record = obj(data);
    const hostnames = arr(record?.hostnames);
    if (!record || !hostnames) return undefined;
    const returned = num(record.returned) ?? hostnames.length;
    const total = num(record.total_count) ?? returned;
    return compose(
        `## Subdomains of ${str(record.apex) ?? 'domain'}`,
        `_Showing ${returned} of ${total} known hostname(s)._`,
        bullets(hostnames as Cell[]),
        str(record.note) && `> ${str(record.note)}`
    );
};

/** Shared by `associated` and `search_domains`, which return identical record shapes. */
function renderDomainRecords(data: unknown, title: string, tool: string): string | undefined {
    const record = obj(data);
    const records = arr(record?.records);
    if (!record || !records) return undefined;
    const rows: Cell[][] = records.map(entry => {
        const item = obj(entry);
        const whois = obj(item?.whois);
        return [
            str(item?.hostname),
            str(whois?.registrar),
            asDate(whois?.createdDate),
            firstOf(item?.host_provider),
            firstOf(item?.mail_provider)
        ];
    });
    const { page, totalPages } = meta(record);
    return compose(
        `## ${title}`,
        table(['Hostname', 'Registrar', 'Created', 'Host provider', 'Mail provider'], rows),
        records.length === 0 ? '_No matching records._' : '',
        pageFooter({ page, totalPages, totalCount: num(record.record_count), tool })
    );
}

export const renderAssociated: Renderer = data =>
    renderDomainRecords(data, 'Associated domains', 'securitytrails_associated');

export const renderSearchDomains: Renderer = data =>
    renderDomainRecords(data, 'Matching domains', 'securitytrails_search_domains');

export const renderDnsHistory: Renderer = data => {
    const record = obj(data);
    const records = arr(record?.records);
    if (!record || !records) return undefined;
    const rows: Cell[][] = records.map(entry => {
        const item = obj(entry);
        const values = arr(item?.values) ?? [];
        return [
            values.map(primaryValue).filter(Boolean).join(', ') || '—',
            joinList(item?.organizations),
            asDate(item?.first_seen),
            asDate(item?.last_seen)
        ];
    });
    const { page, totalPages } = meta(record);
    return compose(
        `## Historical ${String(record.type ?? '').toUpperCase() || 'DNS'} records`,
        table(['Value(s)', 'Organization(s)', 'First seen', 'Last seen'], rows),
        records.length === 0 ? '_No historical records._' : '',
        pageFooter({ page, totalPages, tool: 'securitytrails_dns_history' })
    );
};

export const renderWhoisCurrent: Renderer = data => {
    const record = obj(data);
    if (!record || !str(record.domain)) return undefined;
    const contacts = arr(record.contacts) ?? [];
    const contactRows: Cell[][] = contacts
        .map(obj)
        .filter((contact): contact is Record<string, unknown> => Boolean(contact))
        .map(contact => [
            str(contact.type),
            str(contact.organization) ?? str(contact.name),
            str(contact.email),
            [str(contact.city), str(contact.state), str(contact.country)].filter(Boolean).join(', ') || undefined
        ])
        // Contacts are frequently all-null under privacy services; showing empty rows is noise.
        .filter(row => row.slice(1).some(Boolean));

    return compose(
        `## WHOIS for ${str(record.domain)}`,
        fields([
            ['Registrar', str(record.registrarName)],
            ['Created', asDate(record.createdDate)],
            ['Updated', asDate(record.updatedDate)],
            ['Expires', asDate(record.expiresDate)],
            ['Status', str(record.status)],
            ['Nameservers', arr(record.nameServers) ? joinList(record.nameServers) : undefined]
        ]),
        contactRows.length > 0
            ? compose('### Contacts', table(['Type', 'Organization', 'Email', 'Location'], contactRows))
            : '_All contact fields are empty or redacted._'
    );
};

export const renderWhoisHistory: Renderer = data => {
    const record = obj(data);
    const result = obj(record?.result);
    const items = arr(result?.items);
    if (!items) return undefined;
    const rows: Cell[][] = items.map(entry => {
        const item = obj(entry);
        return [
            asDate(item?.started),
            asDate(item?.ended),
            str(item?.registrarName),
            asDate(item?.createdDate),
            asDate(item?.expiresDate),
            joinList(item?.nameServers),
            item?.private_registration === true ? 'yes' : 'no'
        ];
    });
    return compose(
        '## WHOIS history',
        table(['From', 'Until', 'Registrar', 'Created', 'Expires', 'Nameservers', 'Private'], rows),
        items.length === 0 ? '_No historical WHOIS records._' : '',
        pageFooter({ totalCount: num(result?.count) })
    );
};

export const renderSsl: Renderer = data => {
    const record = obj(data);
    const records = arr(record?.records);
    if (!record || !records) return undefined;
    const rows: Cell[][] = records.map(entry => {
        const item = obj(entry);
        const subject = obj(item?.subject);
        const issuer = obj(item?.issuer);
        const key = obj(item?.public_key);
        const bits = num(key?.bit_length);
        return [
            str(subject?.common_name),
            joinList(item?.dns_names),
            str(issuer?.common_name) ?? firstOf(issuer?.organization),
            asDate(item?.not_before),
            asDate(item?.not_after),
            [str(key?.key_type), bits ? `${bits}-bit` : undefined].filter(Boolean).join(' ') || undefined
        ];
    });
    const { page, totalPages } = meta(record);
    return compose(
        '## SSL/TLS certificates',
        table(['Common name', 'SAN entries', 'Issuer', 'Valid from', 'Valid to', 'Key'], rows),
        records.length === 0 ? '_No certificates for this filter. Try `status: "all"` to include expired ones._' : '',
        pageFooter({ page, totalPages, tool: 'securitytrails_ssl' })
    );
};

export const renderTags: Renderer = data => {
    const record = obj(data);
    const tags = arr(record?.tags);
    if (!tags) return undefined;
    return tags.length === 0
        ? '_SecurityTrails holds no classification tags for this domain._'
        : compose('## Tags', bullets(tags as Cell[]));
};

// ---- IP ---------------------------------------------------------------------

export const renderIpNeighbors: Renderer = data => {
    const record = obj(data);
    const blocks = arr(record?.blocks);
    if (!record || !blocks) return undefined;
    const rows: Cell[][] = blocks.map(entry => {
        const item = obj(entry);
        const hostnames = arr(item?.hostnames) ?? [];
        return [
            str(item?.ip),
            num(item?.sites),
            hostnames.length === 0 ? '—' : joinList(hostnames.slice(0, 4)) + (hostnames.length > 4 ? ', …' : ''),
            joinList(item?.ports)
        ];
    });
    return compose(
        '## Neighbouring IP blocks',
        table(['Block', 'Sites', 'Sample hostnames', 'Open ports'], rows),
        blocks.length === 0 ? '_No neighbouring blocks recorded._' : ''
    );
};

export const renderIpWhois: Renderer = data => {
    const outer = obj(data);
    const record = obj(outer?.record);
    if (!record) return undefined;
    const contacts = arr(record.contacts) ?? [];
    const rows: Cell[][] = contacts.map(entry => {
        const contact = obj(entry);
        return [
            str(contact?.type),
            str(contact?.organization),
            str(contact?.email),
            [
                str(contact?.street1),
                str(contact?.city),
                str(contact?.state),
                str(contact?.postal_code),
                str(contact?.country)
            ]
                .filter(Boolean)
                .join(', ') || undefined
        ];
    });
    return compose(
        `## IP WHOIS for ${str(record.ip) ?? 'address'}`,
        fields([['Source', str(record.source)]]),
        table(['Type', 'Organization', 'Email', 'Address'], rows),
        contacts.length === 0 ? '_No contact records._' : ''
    );
};

// ---- generic ----------------------------------------------------------------

/** Columns worth showing first when flattening an unknown record shape. */
const PREFERRED_KEYS = ['ip', 'hostname', 'user_agent', 'domain', 'value', 'name', 'type', 'last_seen', 'first_seen'];
const MAX_COLUMNS = 8;

/**
 * Fallback for endpoints whose exact shape is plan-gated and therefore unverified here
 * (`ip_useragents`, `company_associated_ips`) and for `scroll`, which echoes whichever search
 * produced it. Flattens scalar fields of `records` into a table.
 */
export const renderRecords: Renderer = data => {
    const record = obj(data);
    const records = arr(record?.records);
    if (!record || !records) return undefined;
    if (records.length === 0) return '_No records._';

    const scalarKeys = new Set<string>();
    for (const entry of records.slice(0, 20)) {
        const item = obj(entry);
        if (!item) return undefined;
        for (const [key, value] of Object.entries(item)) {
            if (value === null || typeof value !== 'object') scalarKeys.add(key);
        }
    }
    if (scalarKeys.size === 0) return undefined;

    const ordered = [
        ...PREFERRED_KEYS.filter(key => scalarKeys.has(key)),
        ...[...scalarKeys].filter(key => !PREFERRED_KEYS.includes(key)).sort()
    ].slice(0, MAX_COLUMNS);

    const rows: Cell[][] = records.map(entry => {
        const item = obj(entry) ?? {};
        return ordered.map(key => {
            const value = item[key];
            return key.endsWith('_seen') || key.endsWith('Date') ? asDate(value) : (value as Cell);
        });
    });

    const { page, totalPages } = meta(record);
    const omitted = scalarKeys.size > ordered.length;
    return compose(
        table(ordered, rows),
        omitted ? '_Some fields omitted. Use `response_format: "json"` for the complete payload._' : '',
        pageFooter({ page, totalPages, totalCount: num(record.record_count) })
    );
};
