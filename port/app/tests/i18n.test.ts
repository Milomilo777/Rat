import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('i18n hardcoded string check', () => {
    it('should not contain hardcoded UI strings in main.ts', () => {
        const mainTs = readFileSync(join(__dirname, '../src/main.ts'), 'utf-8');

        // These are the strings that should be translated
        const forbiddenStrings = [
            'Apps (by Service)',
            'Inspector',
            '>App:<',
            '>Via:<',
            '>Local:<',
            '>Remote:<',
            '>Network Owner:<',
            '>VPN:<',
            '>Proxy:<',
            '>Service:<',
            'World Map (Offline SVG)',
            'Simulate Connection Alert Window',
            '>Profiles<',
            'Default Profile',
            'Rules Table',
            '>Action<',
            '>GeoIP Databases<',
            // these exist in JS function calls: "alert('Update Database trigger')"
            // we will exclude matching those exact JS triggers
            '>Update Database<',
            '>Choose File...<',
            'Monitor network traffic and manage connection rules.',
            'Rat Network Monitor',
            '>Monitor<',
            '>Rules<',
            '>Settings<'
        ];

        for (const str of forbiddenStrings) {
            expect(mainTs).not.toContain(str);
        }
    });
});
