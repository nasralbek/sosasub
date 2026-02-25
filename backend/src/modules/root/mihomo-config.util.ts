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
 * Извлекает базовое имя страны из имени прокси: "germanypg" → "germany", "wl_russia_tw_pg" → "wl_russia_tw"
 */
function getBaseName(proxyName: string): string {
    return proxyName.replace(/pg$/i, '');
}

/**
 * Ищет в списке групп панели группу, в имени которой (без эмодзи) содержится baseName.
 * "germany" → "🇩🇪 Germany"
 */
function findDisplayGroupName(baseName: string, panelGroupNames: string[]): string | null {
    const lower = baseName.toLowerCase();
    for (const gn of panelGroupNames) {
        const stripped = gn
            .replace(/[\p{Emoji}\p{Emoji_Presentation}\p{Extended_Pictographic}]/gu, '')
            .trim()
            .toLowerCase();
        if (stripped === lower) return gn;
    }
    return null;
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

    // Убираем wl_ прокси
    const filtered = pgProxies.filter((p) => !p.name.startsWith('wl_'));
    logger.log(`mihomo: after wl_ filter: ${filtered.length} proxies`);

    // Группируем по базовому имени
    const baseGroups = new Map<string, MihomoProxy[]>();
    for (const p of filtered) {
        const base = getBaseName(p.name);
        const list = baseGroups.get(base) ?? [];
        list.push(p);
        baseGroups.set(base, list);
    }

    // Берём порядок и имена групп из панели (select группа)
    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const selectGroup = panelGroups.find((g) => g.type === 'select');
    const mainGroupName = selectGroup?.name ?? 'Sosa';
    const panelGroupNames: string[] = selectGroup?.proxies ?? [];

    logger.log(`mihomo: mainGroup="${mainGroupName}", panel locations=${panelGroupNames.length}`);

    // Маппинг baseName → displayName из панели
    const baseToDisplay = new Map<string, string>();
    for (const base of baseGroups.keys()) {
        const display = findDisplayGroupName(base, panelGroupNames);
        if (display) {
            baseToDisplay.set(base, display);
        } else {
            logger.warn(`mihomo: no panel group for base="${base}", skipping`);
        }
    }

    // Создаём прокси с уникальными именами
    const modifiedProxies: MihomoProxy[] = [];
    const displayToShortNames = new Map<string, string[]>();

    for (const [base, proxies] of baseGroups.entries()) {
        const display = baseToDisplay.get(base);
        if (!display) continue;

        for (let i = 0; i < proxies.length; i++) {
            const shortName = proxies.length === 1 ? `${base}1pg` : `${base}${i + 1}pg`;
            modifiedProxies.push({ ...proxies[i], name: shortName });

            const list = displayToShortNames.get(display) ?? [];
            list.push(shortName);
            displayToShortNames.set(display, list);
        }
    }

    // Собираем proxy-groups
    const proxyGroups: MihomoProxyGroup[] = [];

    // Определяем порядок в Sosa: добавляем 🇪🇺 Fastest + все страны из панели
    const sosaProxies: string[] = ['🇪🇺 Fastest'];
    for (const name of panelGroupNames) {
        if (displayToShortNames.has(name)) {
            sosaProxies.push(name);
        }
    }

    proxyGroups.push({
        name: mainGroupName,
        type: 'select',
        proxies: sosaProxies,
        hidden: false,
    });

    // 🇪🇺 Fastest — все не-russia
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

    // По каждой стране — url-test
    for (const displayName of panelGroupNames) {
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
    logger.log(`mihomo: done, proxies=${modifiedProxies.length}, groups=${proxyGroups.length}, output=${out.length} chars`);
    return out;
}
