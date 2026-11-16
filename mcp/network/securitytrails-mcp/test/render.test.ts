/**
 * Renderer tests. Fixtures mirror real SecurityTrails payloads captured from the live API,
 * including its mixed second/millisecond timestamp units.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
    renderAssociated,
    renderDnsHistory,
    renderDomainDetails,
    renderIpNeighbors,
    renderIpWhois,
    renderRecords,
    renderSsl,
    renderTags,
    renderWhoisCurrent,
    renderWhoisHistory
} from '../src/render.js';

describe('renderDomainDetails', () => {
    const payload = {
        hostname: 'iana.org',
        apex_domain: 'iana.org',
        subdomain_count: 1,
        current_dns: {
            a: { values: [{ ip: '192.0.43.8', ip_organization: 'ICANN' }], first_seen: '2019-10-25' },
            mx: { values: [{ priority: 10, hostname: 'pechora8.icann.org', hostname_organization: 'ICANN' }] },
            soa: { values: [{ email: 'noc.dns.icann.org', ttl: 7200 }] },
            txt: { values: [{ value: 'v=spf1 -all' }] }
        }
    };

    it('renders each record type with its organisation', () => {
        const output = renderDomainDetails(payload)!;
        assert.match(output, /## iana\.org/);
        assert.match(output, /### A _\(first seen 2019-10-25\)_/);
        assert.match(output, /192\.0\.43\.8 \| ICANN/);
        assert.match(output, /v=spf1 -all/);
    });

    it('prefixes MX values with their priority', () => {
        assert.match(renderDomainDetails(payload)!, /10 pechora8\.icann\.org/);
    });

    it('shows a TTL column only for the record types that carry one', () => {
        const output = renderDomainDetails(payload)!;
        const soaSection = output.slice(output.indexOf('### SOA'));
        assert.match(soaSection, /TTL/);
        const aSection = output.slice(output.indexOf('### A'), output.indexOf('### MX'));
        assert.doesNotMatch(aSection, /TTL/);
    });

    it('declines a payload with no current_dns block', () => {
        assert.equal(renderDomainDetails({ hostname: 'x.com' }), undefined);
    });
});

describe('renderWhoisCurrent', () => {
    it('converts dates and drops all-null privacy contacts', () => {
        const output = renderWhoisCurrent({
            domain: 'example.com',
            registrarName: 'RESERVED-Internet Assigned Numbers Authority',
            createdDate: '1995-08-14T00:00:00Z',
            expiresDate: '2027-08-13T00:00:00Z',
            contacts: [{ type: 'technicalContact', organization: null, email: null, city: null }]
        })!;
        assert.match(output, /\*\*Created:\*\* 1995-08-14/);
        assert.doesNotMatch(output, /T00:00:00Z/);
        assert.match(output, /redacted/);
    });

    it('keeps a contact that has real data', () => {
        const output = renderWhoisCurrent({
            domain: 'example.com',
            contacts: [{ type: 'registrant', organization: 'ICANN', email: 'a@b.c', city: 'LA' }]
        })!;
        assert.match(output, /ICANN/);
        assert.match(output, /a@b\.c/);
    });
});

describe('renderWhoisHistory', () => {
    it('converts millisecond epochs into readable dates', () => {
        const output = renderWhoisHistory({
            result: {
                count: 5,
                items: [
                    {
                        started: 1666169482000,
                        ended: 1666169482000,
                        registrarName: 'CSC Corporate Domains, Inc.',
                        createdDate: 802310400000,
                        expiresDate: 1828224000000,
                        nameServers: ['ns.icann.org'],
                        private_registration: false
                    }
                ]
            }
        })!;
        assert.match(output, /1995-06-05/, 'createdDate in ms must not be read as seconds');
        assert.match(output, /2022-10-19/);
        assert.doesNotMatch(output, /802310400000/);
        assert.match(output, /5 record\(s\) total/);
    });
});

describe('renderSsl', () => {
    it('converts second-based validity epochs and lists SAN entries', () => {
        const output = renderSsl({
            records: [
                {
                    subject: { common_name: '*.iana.org' },
                    issuer: { common_name: 'Sectigo Public Server Authentication CA' },
                    public_key: { key_type: 'RSA', bit_length: 2048 },
                    not_before: 1764979200,
                    not_after: 1799193599,
                    dns_names: ['*.iana.org', 'iana.org']
                }
            ],
            meta: { page: 1, total_pages: 1 }
        })!;
        assert.match(output, /2025-12-06/);
        assert.match(output, /\*\.iana\.org, iana\.org/);
        assert.match(output, /RSA 2048-bit/);
    });

    it('suggests status "all" when a valid-only filter returns nothing', () => {
        assert.match(renderSsl({ records: [] })!, /status: "all"/);
    });
});

describe('renderDnsHistory', () => {
    it('collapses value objects to their salient scalar', () => {
        const output = renderDnsHistory({
            type: 'ns',
            records: [
                {
                    type: 'ns',
                    values: [{ nameserver: 'a.iana-servers.net' }, { nameserver: 'b.iana-servers.net' }],
                    organizations: ['ICANN'],
                    first_seen: '2012-12-23',
                    last_seen: '2026-09-18'
                }
            ],
            pages: 1
        })!;
        assert.match(output, /Historical NS records/);
        assert.match(output, /a\.iana-servers\.net, b\.iana-servers\.net/);
        assert.match(output, /2012-12-23/);
    });
});

describe('renderAssociated', () => {
    it('renders records and offers the next page', () => {
        const output = renderAssociated({
            records: [
                {
                    hostname: 'ietf.org',
                    whois: { registrar: 'CSC', createdDate: 802324800000 },
                    host_provider: ['ICANN'],
                    mail_provider: ['ICANN']
                }
            ],
            meta: { page: 1, total_pages: 2 },
            record_count: 14
        })!;
        assert.match(output, /ietf\.org/);
        assert.match(output, /1995-06-05/);
        assert.match(output, /`page: 2`/);
    });
});

describe('renderIpNeighbors and renderIpWhois', () => {
    it('summarises blocks and caps the hostname sample', () => {
        const output = renderIpNeighbors({
            blocks: [{ ip: '8.8.8.0/32', sites: 11, hostnames: ['a', 'b', 'c', 'd', 'e'], ports: [] }]
        })!;
        assert.match(output, /8\.8\.8\.0\/32/);
        assert.match(output, /a, b, c, d, …/, 'should cap the sample and mark it elided');
    });

    it('joins an IP contact address into one column', () => {
        const output = renderIpWhois({
            record: {
                ip: '8.8.8.8',
                source: 'GOOGLE',
                contacts: [
                    {
                        type: 'registrant',
                        organization: 'Google LLC',
                        street1: '1600 Amphitheatre Parkway',
                        city: 'Mountain View',
                        state: 'CA',
                        postal_code: '94043',
                        country: 'US'
                    }
                ]
            }
        })!;
        assert.match(output, /Google LLC/);
        assert.match(output, /1600 Amphitheatre Parkway, Mountain View, CA, 94043, US/);
    });
});

describe('renderTags', () => {
    it('says so plainly when there are no tags', () => {
        assert.match(renderTags({ tags: [] })!, /no classification tags/);
    });

    it('lists tags when present', () => {
        assert.match(renderTags({ tags: ['cdn', 'hosting'] })!, /- cdn/);
    });
});

describe('renderRecords (generic fallback)', () => {
    it('flattens scalar fields and converts date-like keys', () => {
        const output = renderRecords({
            records: [{ ip: '1.2.3.4', last_seen: 1614078293, nested: { skip: true } }],
            record_count: 1
        })!;
        assert.match(output, /1\.2\.3\.4/);
        assert.match(output, /2021-02-23/);
    });

    it('flags that fields were omitted when a record is very wide', () => {
        const wide: Record<string, unknown> = {};
        for (let index = 0; index < 12; index++) wide[`field_${index}`] = index;
        assert.match(renderRecords({ records: [wide] })!, /response_format: "json"/);
    });

    it('declines a payload with no records array', () => {
        assert.equal(renderRecords({ blocks: [] }), undefined);
    });
});
