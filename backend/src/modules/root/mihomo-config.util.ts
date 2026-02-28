import { Logger } from '@nestjs/common';
import { parse, stringify } from 'yaml';

const logger = new Logger('MihomoConfig');

const URL_TEST_URL = 'https://www.gstatic.com/generate_204';
const URL_TEST_INTERVAL = 60;
const URL_TEST_TIMEOUT = 4000;
const URL_TEST_MAX_FAILED_TIMES = 3;
const FASTEST_GROUP_NAME = '\u{1F1EA}\u{1F1FA} Fastest';

const PROVIDER_ORDER = ['timeweb', 'vk', 'yandex'] as const;
type TWlProvider = (typeof PROVIDER_ORDER)[number];

interface MihomoProxy {
    name: string;
    type: string;
    server?: string;
    port?: number;
    uuid?: string;
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

function isFastestGroupName(name: string): boolean {
    return name.toLowerCase().includes('fastest');
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

function isChildProxy(name: string): boolean {
    const withoutEmoji = name.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();
    return /\d/.test(withoutEmoji);
}

function detectRussiaWlProvider(name: string): TWlProvider | null {
    const short = toShortName(name);

    if (!short.includes('wlrussia')) {
        return null;
    }

    if (short.includes('timeweb') || short.includes('tw')) {
        return 'timeweb';
    }

    if (short.includes('vk')) {
        return 'vk';
    }

    if (short.includes('yandex') || short.includes('ya')) {
        return 'yandex';
    }

    return null;
}

function ensureUniqueName(baseName: string, usedNames: Set<string>): string {
    if (!usedNames.has(baseName)) {
        usedNames.add(baseName);
        return baseName;
    }

    let idx = 2;
    while (usedNames.has(`${baseName}_${idx}`)) {
        idx += 1;
    }

    const uniqueName = `${baseName}_${idx}`;
    usedNames.add(uniqueName);
    return uniqueName;
}

function withUuid(proxy: MihomoProxy, uuid: string | undefined): MihomoProxy {
    if (!uuid) {
        return proxy;
    }

    return {
        ...proxy,
        uuid,
    };
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

    const baseChildProxies = rawProxies.filter((p) => !isWlProxy(p.name) && isChildProxy(p.name));
    const parentProxies = rawProxies.filter((p) => !isWlProxy(p.name) && !isChildProxy(p.name));
    const wlRussiaTemplates = rawProxies.filter((p) => detectRussiaWlProvider(p.name) !== null);

    logger.log(
        `mihomo: base children=${baseChildProxies.length}, parents=${parentProxies.length}, wl russia templates=${wlRussiaTemplates.length}`,
    );

    const panelGroups = (doc['proxy-groups'] as MihomoProxyGroup[] | undefined) ?? [];
    const selectGroup = panelGroups.find((g) => g.type === 'select');
    const mainGroupName = selectGroup?.name ?? 'Sosa';
    const panelSelectList: string[] = selectGroup?.proxies ?? [];

    const sosaGroupNames = getGroupNamesWithoutNumbers(panelSelectList);
    const panelCountryGroupNames = sosaGroupNames.filter((groupName) => !isFastestGroupName(groupName));
    logger.log(
        `mihomo: mainGroup="${mainGroupName}", panel select list=${panelSelectList.length}, sosa groups=${sosaGroupNames.length}`,
    );

    const parentByLocation = new Map<string, MihomoProxy>();
    for (const parentProxy of parentProxies) {
        const locationName = getLocationGroupName(parentProxy.name);
        if (!parentByLocation.has(locationName)) {
            parentByLocation.set(locationName, parentProxy);
        }
    }

    const fallbackCountryGroupNames =
        panelCountryGroupNames.length > 0
            ? panelCountryGroupNames
            : Array.from(parentByLocation.keys());

    const wlTemplatesByProvider = new Map<TWlProvider, MihomoProxy[]>(
        PROVIDER_ORDER.map((provider) => [provider, []]),
    );
    for (const template of wlRussiaTemplates) {
        const provider = detectRussiaWlProvider(template.name);
        if (!provider) continue;
        wlTemplatesByProvider.get(provider)!.push(template);
    }

    const modifiedProxies: MihomoProxy[] = [];
    const subgroupToProxies = new Map<string, string[]>();
    const countryToSubgroups = new Map<string, string[]>();
    const generatedCountryGroupNames: string[] = [];
    const usedProxyNames = new Set<string>();

    for (const countryGroupName of fallbackCountryGroupNames) {
        const parent = parentByLocation.get(countryGroupName);
        if (!parent) {
            logger.warn(`mihomo: parent proxy not found for country group "${countryGroupName}", skipping`);
            continue;
        }

        const countrySlug = toShortName(countryGroupName);
        if (!countrySlug) {
            logger.warn(`mihomo: failed to build country slug for "${countryGroupName}", skipping`);
            continue;
        }

        const parentUuid = typeof parent.uuid === 'string' ? parent.uuid : undefined;
        if (!parentUuid) {
            logger.warn(`mihomo: parent "${countryGroupName}" has no uuid, using original child/template uuid`);
        }

        const countrySubgroups: string[] = [];

        const countryBaseChildren = baseChildProxies.filter(
            (proxy) => getLocationGroupName(proxy.name) === countryGroupName,
        );

        if (countryBaseChildren.length > 0) {
            const baseSubgroupName = countrySlug;
            const baseProxyNames: string[] = [];

            countryBaseChildren.forEach((proxy, index) => {
                const desiredName = `${countrySlug}${index + 1}`;
                const proxyName = ensureUniqueName(desiredName, usedProxyNames);
                const clonedProxy = withUuid({ ...proxy, name: proxyName }, parentUuid);
                modifiedProxies.push(clonedProxy);
                baseProxyNames.push(proxyName);
            });

            subgroupToProxies.set(baseSubgroupName, baseProxyNames);
            countrySubgroups.push(baseSubgroupName);
        }

        for (const provider of PROVIDER_ORDER) {
            const providerTemplates = wlTemplatesByProvider.get(provider) ?? [];
            if (providerTemplates.length === 0) continue;

            const subgroupName = `${countrySlug}_${provider}`;
            const providerProxyNames: string[] = [];

            providerTemplates.forEach((template, index) => {
                const desiredName = `${countrySlug}_${provider}_${index + 1}`;
                const proxyName = ensureUniqueName(desiredName, usedProxyNames);
                const clonedProxy = withUuid({ ...template, name: proxyName }, parentUuid);
                modifiedProxies.push(clonedProxy);
                providerProxyNames.push(proxyName);
            });

            subgroupToProxies.set(subgroupName, providerProxyNames);
            countrySubgroups.push(subgroupName);
        }

        if (countrySubgroups.length === 0) {
            logger.warn(`mihomo: country "${countryGroupName}" has no generated subgroups, skipping`);
            continue;
        }

        generatedCountryGroupNames.push(countryGroupName);
        countryToSubgroups.set(countryGroupName, countrySubgroups);
    }

    logger.log(`mihomo: modified proxies=${modifiedProxies.length}, countries=${generatedCountryGroupNames.length}`);

    if (modifiedProxies.length === 0 || generatedCountryGroupNames.length === 0) {
        logger.warn('mihomo: generated config is empty, returning original');
        return rawYaml;
    }

    const proxyGroups: MihomoProxyGroup[] = [];

    const mainSelectProxies = [FASTEST_GROUP_NAME, ...generatedCountryGroupNames];

    proxyGroups.push({
        name: mainGroupName,
        type: 'select',
        proxies: mainSelectProxies,
        hidden: false,
    });

    proxyGroups.push({
        name: FASTEST_GROUP_NAME,
        type: 'url-test',
        hidden: true,
        proxies: generatedCountryGroupNames,
        url: URL_TEST_URL,
        interval: URL_TEST_INTERVAL,
        timeout: URL_TEST_TIMEOUT,
        lazy: false,
        'max-failed-times': URL_TEST_MAX_FAILED_TIMES,
    });

    for (const countryGroupName of generatedCountryGroupNames) {
        const countrySubgroups = countryToSubgroups.get(countryGroupName);
        if (!countrySubgroups || countrySubgroups.length === 0) continue;

        proxyGroups.push({
            name: countryGroupName,
            type: 'fallback',
            hidden: true,
            proxies: countrySubgroups,
            url: URL_TEST_URL,
            interval: URL_TEST_INTERVAL,
            timeout: URL_TEST_TIMEOUT,
            lazy: false,
            'max-failed-times': URL_TEST_MAX_FAILED_TIMES,
        });

        for (const subgroupName of countrySubgroups) {
            const subgroupProxies = subgroupToProxies.get(subgroupName);
            if (!subgroupProxies || subgroupProxies.length === 0) continue;

            proxyGroups.push({
                name: subgroupName,
                type: 'url-test',
                hidden: true,
                proxies: subgroupProxies,
                url: URL_TEST_URL,
                interval: URL_TEST_INTERVAL,
                timeout: URL_TEST_TIMEOUT,
                lazy: false,
                'max-failed-times': URL_TEST_MAX_FAILED_TIMES,
            });
        }
    }

    doc.proxies = modifiedProxies;
    doc['proxy-groups'] = proxyGroups;

    const out = stringify(doc, { lineWidth: 0 });
    logger.log(
        `mihomo: done, proxies=${modifiedProxies.length}, groups=${proxyGroups.length}, output=${out.length} chars`,
    );
    return out;
}
