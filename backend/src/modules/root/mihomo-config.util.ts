import { parse, stringify } from 'yaml';

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

function toShortName(displayName: string): string {
    return displayName
        .replace(/[\p{Emoji}\p{Emoji_Presentation}\p{Extended_Pictographic}]/gu, '')
        .replace(/\s+/g, '')
        .trim()
        .toLowerCase();
}

function toGroupDisplayName(originalName: string): string {
    return originalName.replace(/\d+pg$/i, '').trim();
}

function isPgProxy(proxy: MihomoProxy): boolean {
    return typeof (proxy as MihomoProxy & { encryption?: string }).encryption === 'string';
}

/**
 * Берёт из конфига панели порядок и названия локаций из главной select-группы (proxy-groups).
 */
function getLocationOrderFromPanel(doc: Record<string, unknown>): { mainGroupName: string; locationOrder: string[] } {
    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const mainSelect = panelGroups.find((g) => g.type === 'select');
    if (mainSelect?.proxies?.length) {
        return {
            mainGroupName: mainSelect.name,
            locationOrder: mainSelect.proxies,
        };
    }
    return { mainGroupName: 'Sosa', locationOrder: [] };
}

/**
 * Модифицирует только proxies и proxy-groups в конфиге mihomo.
 * Всё остальное (mixed-port, dns, rules и т.д.) остаётся из ответа панели.
 */
export function modifyMihomoConfig(rawYaml: string): string {
    let doc: Record<string, unknown>;
    try {
        doc = parse(rawYaml) as Record<string, unknown>;
    } catch {
        return rawYaml;
    }

    const rawProxies = (doc.proxies as MihomoProxy[]) ?? [];
    const pgProxies = rawProxies.filter(isPgProxy);

    if (pgProxies.length === 0) {
        return rawYaml;
    }

    const displayToShortNames = new Map<string, string[]>();
    const modifiedProxies: MihomoProxy[] = [];

    for (const p of pgProxies) {
        const shortName = toShortName(p.name);
        const displayName = toGroupDisplayName(p.name);

        const list = displayToShortNames.get(displayName) ?? [];
        list.push(shortName);
        displayToShortNames.set(displayName, list);

        modifiedProxies.push({ ...p, name: shortName });
    }

    const { mainGroupName, locationOrder } = getLocationOrderFromPanel(doc);
    const locationOrderFiltered =
        locationOrder.length > 0
            ? locationOrder.filter((name) => displayToShortNames.has(name))
            : [...displayToShortNames.keys()];

    const proxyGroups: MihomoProxyGroup[] = [
        {
            name: mainGroupName,
            type: 'select',
            proxies: locationOrderFiltered,
            hidden: false,
        },
    ];

    if (locationOrderFiltered.length > 0) {
        proxyGroups.push({
            name: locationOrderFiltered[0],
            type: 'url-test',
            hidden: true,
            proxies: modifiedProxies
                .map((p) => p.name)
                .filter((name) => !name.startsWith('russia')),
            url: URL_TEST_URL,
            interval: URL_TEST_INTERVAL,
            timeout: URL_TEST_TIMEOUT,
            lazy: false,
            'max-failed-times': 1,
            'expected-status': 204,
        });
    }

    for (let i = 1; i < locationOrderFiltered.length; i++) {
        const displayName = locationOrderFiltered[i];
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

    return stringify(doc, { lineWidth: 0 });
}
