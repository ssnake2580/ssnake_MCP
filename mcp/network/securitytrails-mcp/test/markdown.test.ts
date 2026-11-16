import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { asDate, cell, epochToDate, fields, pageFooter, table } from '../src/markdown.js';

describe('epochToDate', () => {
    it('reads a seconds-based timestamp', () => {
        // 1764979200 = 2025-12-06, an SSL not_before value.
        assert.equal(epochToDate(1764979200), '2025-12-06');
    });

    it('reads a millisecond timestamp that would be absurd as seconds', () => {
        // 802310400000 = 1995-06-05, iana.org's WHOIS createdDate.
        assert.equal(epochToDate(802310400000), '1995-06-05');
    });

    it('reads a modern millisecond timestamp', () => {
        assert.equal(epochToDate(1666169482000), '2022-10-19');
    });

    it('ignores zero, negatives and non-numbers', () => {
        assert.equal(epochToDate(0), undefined);
        assert.equal(epochToDate(-5), undefined);
        assert.equal(epochToDate('1764979200'), undefined);
        assert.equal(epochToDate(null), undefined);
        assert.equal(epochToDate(Number.NaN), undefined);
    });
});

describe('asDate', () => {
    it('passes a plain ISO date through', () => {
        assert.equal(asDate('2026-09-18'), '2026-09-18');
    });

    it('drops an empty time component', () => {
        assert.equal(asDate('1995-08-14T00:00:00Z'), '1995-08-14');
    });

    it('converts epochs and ignores blanks', () => {
        assert.equal(asDate(802310400000), '1995-06-05');
        assert.equal(asDate(''), undefined);
        assert.equal(asDate('   '), undefined);
    });
});

describe('table', () => {
    it('escapes pipes so a cell cannot break the table', () => {
        const rendered = table(['A'], [['x | y']]);
        assert.match(rendered, /x \\\| y/);
        assert.equal(rendered.split('\n').length, 3, 'header, rule, one row');
    });

    it('flattens newlines inside a cell', () => {
        assert.match(table(['A'], [['line1\nline2']]), /line1 line2/);
    });

    it('returns nothing for zero rows, so empty sections can be dropped', () => {
        assert.equal(table(['A', 'B'], []), '');
    });
});

describe('cell', () => {
    it('renders absent values as a dash', () => {
        assert.equal(cell(null), '—');
        assert.equal(cell(undefined), '—');
        assert.equal(cell(''), '—');
    });

    it('preserves zero and false rather than treating them as absent', () => {
        assert.equal(cell(0), '0');
        assert.equal(cell(false), 'false');
    });
});

describe('fields', () => {
    it('omits entries with no value', () => {
        const rendered = fields([
            ['Registrar', 'CSC'],
            ['Updated', undefined],
            ['Expires', '']
        ]);
        assert.equal(rendered, '**Registrar:** CSC');
    });

    it('returns an empty string when nothing is present', () => {
        assert.equal(fields([['A', null]]), '');
    });
});

describe('pageFooter', () => {
    it('names the next page and warns that it costs a query', () => {
        const footer = pageFooter({ page: 1, totalPages: 3, totalCount: 59, tool: 'securitytrails_associated' });
        assert.match(footer, /59 record\(s\) total/);
        assert.match(footer, /page 1 of 3/);
        assert.match(footer, /`page: 2`/);
        assert.match(footer, /API query/);
    });

    it('does not offer a next page on the last one', () => {
        const footer = pageFooter({ page: 3, totalPages: 3, totalCount: 10 });
        assert.doesNotMatch(footer, /page: 4/);
    });

    it('is empty when there is nothing to report', () => {
        assert.equal(pageFooter({}), '');
    });
});
