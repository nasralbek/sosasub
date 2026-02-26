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

function isPgProxy(proxy: MihomoProxy): boolean {
    return typeof (proxy as MihomoProxy & { encryption?: string }).encryption === 'string';
}

/**
 * Та же логика что и createTagFromRemarks в xray модификаторе:
 * "🇵🇱 Poland1pg" → "poland1pg"
 * "🇩🇪 Germany3pg" → "germany3pg"
 * "🇷🇺 WL_RUSSIA_TW_1pg" → "wlrussiatw1pg"
 */
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

/**
 * "🇵🇱 Poland1pg" → "Poland"
 * "🇩🇪 Germany3pg" → "Germany"
 */
function extractCountryName(name: string): string {
    const withoutEmoji = name.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();
    return withoutEmoji.replace(/\d+pg$/i, '').trim();
}

/**
 * "🇵🇱 Poland1pg" → "🇵🇱 Poland"
 */
function toDisplayGroupName(name: string): string {
    const flag = extractFlagEmoji(name);
    const country = extractCountryName(name);
    return flag ? `${flag} ${country}` : country;
}

function isWlProxy(name: string): boolean {
    return name.includes('WL_') || toShortName(name).startsWith('wl');
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
    const pgProxies = rawProxies.filter(isPgProxy);

    logger.log(`mihomo: total proxies=${rawProxies.length}, pg=${pgProxies.length}`);

    if (pgProxies.length === 0) {
        logger.warn('mihomo: no pg proxies found, returning original');
        return rawYaml;
    }

    const filtered = pgProxies.filter((p) => !isWlProxy(p.name));
    logger.log(`mihomo: after WL_ filter: ${filtered.length} proxies`);

    const displayToShortNames = new Map<string, string[]>();
    const modifiedProxies: MihomoProxy[] = [];
    const groupOrder: string[] = [];

    for (const p of filtered) {
        const shortName = toShortName(p.name);
        const displayName = toDisplayGroupName(p.name);

        modifiedProxies.push({ ...p, name: shortName });

        if (!displayToShortNames.has(displayName)) {
            displayToShortNames.set(displayName, []);
            groupOrder.push(displayName);
        }
        displayToShortNames.get(displayName)!.push(shortName);
    }

    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const selectGroup = panelGroups.find((g) => g.type === 'select');
    const mainGroupName = selectGroup?.name ?? 'Sosa';

    // Панель отдаёт в select-группе отдельные прокси, не страны.
    // Извлекаем уникальные страны в порядке панели.
    const panelLocationOrder: string[] = [];
    const seenLocations = new Set<string>();
    if (selectGroup?.proxies) {
        for (const proxyName of selectGroup.proxies) {
            if (isWlProxy(proxyName)) continue;
            const displayName = toDisplayGroupName(proxyName);
            if (!seenLocations.has(displayName) && displayToShortNames.has(displayName)) {
                seenLocations.add(displayName);
                panelLocationOrder.push(displayName);
            }
        }
    }

    const locationOrder = panelLocationOrder.length > 0 ? panelLocationOrder : groupOrder;

    logger.log(
        `mihomo: mainGroup="${mainGroupName}", locations=${locationOrder.length}, proxies=${modifiedProxies.length}`,
    );

    const proxyGroups: MihomoProxyGroup[] = [];

    proxyGroups.push({
        name: mainGroupName,
        type: 'select',
        proxies: ['🇪🇺 Fastest', ...locationOrder],
        hidden: false,
    });

    const fastestProxies = modifiedProxies
        .map((p) => p.name)
        .filter((name) => !name.startsWith('russia'));

    proxyGroups.push({
        name: '🇪🇺 Fastest',
        type: 'url-test',
        hidden: true,
        proxies: fastestProxies,
        url: URL_TEST_URL,
        interval: URL_TEST_INTERVAL,
        timeout: URL_TEST_TIMEOUT,
        lazy: false,
        'max-failed-times': 1,
        'expected-status': 204,
    });

    for (const displayName of locationOrder) {
        const shortNames = displayToShortNames.get(displayName);
        if (!shortNames?.length) continue;
        proxyGroups.push({
            name: displayName,
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
