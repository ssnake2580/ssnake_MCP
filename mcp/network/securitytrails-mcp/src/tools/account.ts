/** Account-level tools: key validation and quota accounting. */

import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { SecurityTrailsClient } from '../client.js';
import { renderPing, renderUsage } from '../render.js';
import { READ_ONLY, safeStructured } from '../result.js';
import { ResponseFormatSchema } from '../schemas.js';

interface UsageResponse {
    allowed_monthly_usage?: number;
    current_monthly_usage?: number;
}

export function registerAccountTools(server: McpServer, client: SecurityTrailsClient): void {
    server.registerTool(
        'securitytrails_ping',
        {
            title: 'Verify API key',
            description:
                'Check that the configured SecurityTrails API key is accepted. Returns only a success flag — ' +
                'use securitytrails_usage for quota figures.',
            annotations: READ_ONLY,
            inputSchema: z.object({ response_format: ResponseFormatSchema }),
            outputSchema: z.object({
                success: z.boolean().describe('true when the API key is valid')
            })
        },
        safeStructured(async () => {
            const data = await client.request<{ success?: boolean }>('/ping');
            return { success: data.success === true };
        }, renderPing)
    );

    server.registerTool(
        'securitytrails_usage',
        {
            title: 'Check API quota',
            description:
                'Report this month’s SecurityTrails API consumption against the plan allowance. ' +
                'Call this before a large enumeration to confirm there is remaining quota.',
            annotations: READ_ONLY,
            inputSchema: z.object({ response_format: ResponseFormatSchema }),
            outputSchema: z.object({
                allowed_monthly_usage: z.number().describe('queries included in the plan per month'),
                current_monthly_usage: z.number().describe('queries consumed so far this month'),
                remaining: z.number().describe('allowance minus consumption'),
                percent_used: z.number().describe('consumption as a percentage, rounded to one decimal place')
            })
        },
        safeStructured(async () => {
            const data = await client.request<UsageResponse>('/account/usage');
            const allowed = data.allowed_monthly_usage ?? 0;
            const used = data.current_monthly_usage ?? 0;
            return {
                allowed_monthly_usage: allowed,
                current_monthly_usage: used,
                remaining: Math.max(0, allowed - used),
                percent_used: allowed > 0 ? Math.round((used / allowed) * 1000) / 10 : 0
            };
        }, renderUsage)
    );
}
