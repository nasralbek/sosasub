import { Logger } from '@nestjs/common';
import { parse, stringify } from 'yaml';

const logger = new Logger('MihomoConfig');

const URL_TEST_URL = 'https://www.gstatic.com/generate_204';
const URL_TEST_INTERVAL = 30;
const URL_TEST_TIMEOUT = 3000;

interface MihomoProxy {
    name: string;
    type: string;
    server?: string;
    port?: number;
    [key: string]: unknown;
}

interface MihomoProxyGroup {
    name: string;
    type: string;
    proxies: string[];
    hidden?: boolean;
    url?: string;
    interval?: number;
    timeout?: number;
    lazy?: boolean;
    'max-failed-times'?: number;
    'expected-status'?: number;
}

function toShortName(name: string): string {
    const withoutEmoji = name.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '');
    const withoutBrackets = withoutEmoji.replace(/\[.*?\]/g, '');
    const sanitized = withoutBrackets.replace(/[^a-zA-Z0-9]/g, '');
    return sanitized.toLowerCase();
}

function extractFlagEmoji(name: string): string {
    const match = name.match(/[\u{1F1E0}-\u{1F1FF}]{2}/gu);
    return match ? match[0] : '';
}

function getLocationGroupName(proxyName: string): string {
    const flag = extractFlagEmoji(proxyName);
    const withoutEmoji = proxyName.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();
    const base = withoutEmoji.replace(/\d+(pg)?$/i, '').trim();
    return flag ? `${flag} ${base}` : base;
}

function getGroupNamesWithoutNumbers(panelProxies: string[]): string[] {
    const result: string[] = [];
    const seen = new Set<string>();
    for (const name of panelProxies) {
        const withoutEmoji = name.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();
        if (!/\d+(pg)?$/i.test(withoutEmoji)) {
            if (!seen.has(name)) {
                result.push(name);
                seen.add(name);
            }
        }
    }
    return result;
}

function isWlProxy(name: string): boolean {
    const lower = name.toLowerCase();
    return lower.includes('wl_') || toShortName(name).startsWith('wl');
}

export function modifyMihomoConfig(rawYaml: string): string {
    let doc: Record<string, unknown>;
    try {
        doc = parse(rawYaml) as Record<string, unknown>;
    } catch (err) {
        logger.warn('mihomo: YAML parse failed, returning original', err);
        return rawYaml;
    }

    const rawProxies = (doc.proxies as MihomoProxy[]) ?? [];
    logger.log(`mihomo: total proxies=${rawProxies.length}`);

    if (rawProxies.length === 0) {
        logger.warn('mihomo: no proxies found, returning original');
        return rawYaml;
    }

    const filtered = rawProxies.filter((p) => !isWlProxy(p.name));
    logger.log(`mihomo: after WL filter: ${filtered.length} proxies`);

    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const selectGroup = panelGroups.find((g) => g.type === 'select');
    const mainGroupName = selectGroup?.name ?? 'Sosa';
    const panelSelectList: string[] = selectGroup?.proxies ?? [];

    const sosaGroupNames = getGroupNamesWithoutNumbers(panelSelectList);
    logger.log(
        `mihomo: mainGroup="${mainGroupName}", panel select list=${panelSelectList.length}, sosa groups=${sosaGroupNames.length}`,
    );

    const locationToShortNames = new Map<string, string[]>();
    const modifiedProxies: MihomoProxy[] = [];

    for (const p of filtered) {
        const shortName = toShortName(p.name);
        const locationName = getLocationGroupName(p.name);

        modifiedProxies.push({ ...p, name: shortName });

        if (!locationToShortNames.has(locationName)) {
            locationToShortNames.set(locationName, []);
        }
        locationToShortNames.get(locationName)!.push(shortName);
    }

    logger.log(
        `mihomo: modified proxies=${modifiedProxies.length}, locations=${locationToShortNames.size}`,
    );

    const proxyGroups: MihomoProxyGroup[] = [];

    proxyGroups.push({
        name: mainGroupName,
        type: 'select',
        proxies: sosaGroupNames,
        hidden: false,
    });

    const allShortNames = modifiedProxies.map((p) => p.name);
    proxyGroups.push({
        name: '\u{1F1EA}\u{1F1FA} Fastest',
        type: 'url-test',
        hidden: true,
        proxies: allShortNames,
        url: URL_TEST_URL,
        interval: URL_TEST_INTERVAL,
        timeout: URL_TEST_TIMEOUT,
        lazy: false,
        'max-failed-times': 1,
        'expected-status': 204,
    });

    for (const groupName of sosaGroupNames) {
        if (groupName === '\u{1F1EA}\u{1F1FA} Fastest') continue;
        const shortNames = locationToShortNames.get(groupName);
        if (!shortNames?.length) continue;
        proxyGroups.push({
            name: groupName,
            type: 'url-test',
            hidden: true,
            proxies: shortNames,
            url: URL_TEST_URL,
            interval: URL_TEST_INTERVAL,
            timeout: URL_TEST_TIMEOUT,
            lazy: false,
            'max-failed-times': 1,
            'expected-status': 204,
        });
    }

    doc.proxies = modifiedProxies;
    doc['proxy-groups'] = proxyGroups;

    const out = stringify(doc, { lineWidth: 0 });
    logger.log(
        `mihomo: done, proxies=${modifiedProxies.length}, groups=${proxyGroups.length}, output=${out.length} chars`,
    );
    return out;
}
