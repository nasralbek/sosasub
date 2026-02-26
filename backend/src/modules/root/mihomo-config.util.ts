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

/**
 * "polandpg" → "poland"
 * "germany3pg" → "germany3" → мы группируем ниже по стране
 * "🇵🇱 Poland1pg" → "🇵🇱 Poland1"
 */
function stripPgSuffix(name: string): string {
    return name.replace(/pg$/i, '');
}

/**
 * Та же логика что createTagFromRemarks в xray модификаторе:
 * "🇵🇱 Poland1pg" → "poland1pg"
 * "polandpg" → "polandpg"
 */
function toShortName(name: string): string {
    const withoutEmoji = name.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '');
    const withoutBrackets = withoutEmoji.replace(/\[.*?\]/g, '');
    const sanitized = withoutBrackets.replace(/[^a-zA-Z0-9]/g, '');
    return sanitized.toLowerCase();
}

/**
 * Извлекает базовое имя страны для группировки:
 * "polandpg" → "poland"
 * "germany3pg" → "germany"
 * "🇵🇱 Poland1pg" → "poland"
 * "wl_russia_tw_pg" → "wlrussiatw"
 */
function getBaseCountry(name: string): string {
    const short = toShortName(name);
    return short.replace(/\d*pg$/i, '');
}

/**
 * Ищет в списке групп панели группу, чьё имя (без эмодзи, lowercase) совпадает с baseCountry.
 * "poland" → "🇵🇱 Poland"
 */
function findDisplayGroupName(baseCountry: string, panelGroupNames: string[]): string | null {
    const lower = baseCountry.toLowerCase();
    for (const gn of panelGroupNames) {
        const stripped = gn
            .replace(/[\p{Emoji}\p{Emoji_Presentation}\p{Extended_Pictographic}]/gu, '')
            .trim()
            .toLowerCase();
        if (stripped === lower) return gn;
    }
    return null;
}

function isWlProxy(name: string): boolean {
    const lower = name.toLowerCase();
    return lower.startsWith('wl_') || lower.startsWith('wl ') || toShortName(name).startsWith('wl');
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
    logger.log(`mihomo: after WL_ filter: ${filtered.length} proxies`);

    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const selectGroup = panelGroups.find((g) => g.type === 'select');
    const mainGroupName = selectGroup?.name ?? 'Sosa';
    const panelGroupNames: string[] = selectGroup?.proxies ?? [];

    // Группируем прокси по базовому имени страны
    const countryProxies = new Map<string, MihomoProxy[]>();
    const countryOrder: string[] = [];

    for (const p of filtered) {
        const base = getBaseCountry(p.name);
        if (!countryProxies.has(base)) {
            countryProxies.set(base, []);
            countryOrder.push(base);
        }
        countryProxies.get(base)!.push(p);
    }

    // Маппинг baseCountry → displayName из панели
    const baseToDisplay = new Map<string, string>();
    for (const base of countryOrder) {
        const display = findDisplayGroupName(base, panelGroupNames);
        if (display) {
            baseToDisplay.set(base, display);
        } else {
            logger.warn(`mihomo: no panel group for base="${base}", skipping`);
        }
    }

    // Переименовываем прокси с уникальными именами
    const modifiedProxies: MihomoProxy[] = [];
    const displayToShortNames = new Map<string, string[]>();
    const locationOrder: string[] = [];

    for (const base of countryOrder) {
        const display = baseToDisplay.get(base);
        if (!display) continue;

        const proxies = countryProxies.get(base)!;

        if (!displayToShortNames.has(display)) {
            displayToShortNames.set(display, []);
            locationOrder.push(display);
        }

        for (let i = 0; i < proxies.length; i++) {
            const shortName = `${base}${i + 1}pg`;
            modifiedProxies.push({ ...proxies[i], name: shortName });
            displayToShortNames.get(display)!.push(shortName);
        }
    }

    // Используем порядок стран из панели если возможно
    const panelLocationOrder: string[] = [];
    for (const name of panelGroupNames) {
        if (displayToShortNames.has(name)) {
            panelLocationOrder.push(name);
        }
    }
    const finalLocationOrder = panelLocationOrder.length > 0 ? panelLocationOrder : locationOrder;

    logger.log(
        `mihomo: mainGroup="${mainGroupName}", locations=${finalLocationOrder.length}, proxies=${modifiedProxies.length}`,
    );

    // Собираем proxy-groups
    const proxyGroups: MihomoProxyGroup[] = [];

    proxyGroups.push({
        name: mainGroupName,
        type: 'select',
        proxies: ['🇪🇺 Fastest', ...finalLocationOrder],
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

    for (const displayName of finalLocationOrder) {
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
