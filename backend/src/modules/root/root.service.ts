import { AxiosResponseHeaders, RawAxiosResponseHeaders } from 'axios';
import { Request, Response } from 'express';
import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid';

import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Logger } from '@nestjs/common';

import { TRequestTemplateTypeKeys } from '@remnawave/backend-contract';

import { AxiosService } from '@common/axios/axios.service';
import { sanitizeUsername } from '@common/utils';

import bridgeSubscriptionSnapshot from './snapshots/ejx-bridge-subscription.json';
import { modifyMihomoConfig } from './mihomo-config.util';

// Интерфейсы для Xray JSON конфигурации
interface XrayOutbound {
    tag: string;
    protocol: string;
    settings?: unknown;
    streamSettings?: unknown;
    mux?: unknown;
}

interface XrayConfig {
    remarks: string;
    outbounds: XrayOutbound[];
    dns?: unknown;
    log?: unknown;
    stats?: unknown;
    policy?: unknown;
    routing?: unknown;
    inbounds?: unknown[];
}

const BRIDGE_GROUP_ORDER = ['oc', 'vk', 'cv', 'sk', 'yc', 'ng'] as const;
type BridgeGroup = (typeof BRIDGE_GROUP_ORDER)[number];
const BRIDGE_GROUP_TO_SELECTOR: Record<BridgeGroup, string> = {
    cv: 'wlrussiaejxcv',
    ng: 'wlrussiaejxng',
    oc: 'wlrussiaejxoc',
    sk: 'wlrussiaejxsk',
    vk: 'wlrussiaejxvk',
    yc: 'wlrussiaejxyc',
};
const WS_BRIDGE_PORT = 80;
const WS_BRIDGE_ID = '53114c5a-0be7-4234-97b9-358986e73237';
const WS_BRIDGE_ENCRYPTION =
    'mlkem768x25519plus.random.0rtt.AmJbWeMXGJJL90RMRnsbwBVEdctBumGyIYPH5dI4uedV_1m2BYQKOvFfbUOOlheFELQGcsqviapx03HDXRg99dJEt3owPmJvZ5Vb8-SFSCfEv8SsngMnDuIDVEtIEqdkAlqkmvwoCatK0JZuY-HBtcEdl4TOKlE9hFw6RjHK3Jh3wLArgHUBupSNAGmEuBrBG-rP0xgHI8coSEocP2N1H1hf4hIuICqiPFmcuclc5mOfqYsjLKCTKDaIKRCerNWsDEU418pzRFcD5uyz67kYY5xq89F8WUZ6-JcEiQoIG-h5B_JmGYFIb1kEkyZeo4QBUfxd1Bl3-9eVaFwL7uS4YvM6cJYH-JICiOURm0qFBXkCi_yGqzIdV5g57uhJ3KsHWry6bFqzYWid5qlAqEqY-XB4HbaVSeQLfvWgxAxf2AagymeXNDYNU3Yg1DvC6Vd9z5TMmkIcuySwsEWfS0qSrrs5KZG6rUPKP1UM3vRInWV8mmpEUpLAHRfDrzp3PqIEv5cPvDce1OFu5WiuLeenT9SuKzRKd9IGLQRWWWe579Q-r1dgFBSI2-A1ZVmAW3dshHgXgDyJQ0Bzb1GCy2oN82G5hRVHe4d-KsycwXvK-deJn3ZFb3uo_Zir-5IIiUPCsyG_kNNTLESKDQtgqVZyypQEEuu4ChGAJjZoD-yjAnhfY6M0F8Vd_GW3sKu-xUkOfpKRzJKmXvLF1gSKTTSiVtwEc7IYUTqRRwRoQ4u-UCmM_ikO3CSaHWdHjoE2EBCrTVh34bJC6cxkLYMo3epc_zhW1RuKWXkBP-FCc6zBGKJuvACiWrg1s-cwFKVpIPUuJnPNVkgU76ieLlSC0ldCBUc8OaySRbl0JIw_H_uYytR185Jo80exkhCjZAVmvLDFywbBj8EJ3zdPz4QL5UEtHdQQp6QGjmshB1sgWMarJ8oVFEADsDoCUtOGslg5GySmi7OHuJli3vutawvN0TnNt1V4bhU2gPU3lyoUrqpHClR4FVc8IsMnWme4haJyZAep4LoRynuFqRkLVNyY7ZsRAcAFXcoO5MojayMB0NBPcyLE_isMLqikkyzI7Icj-rUhaVlBJfl5GnmURMQz9GUCsdYTeckxZAALqpNJcjO6YWoF6BIyByd2a8dslAJ5FfZOIuM1JqzJ3ls4gxKWpra3w2O4VEKGE6Meo6k-yCcDzrddAWeiOYcAWTsnZ3TB19SwUKRlKnFbggw7AUstF3aSJePHtyqDveDFKdGadkaH16rLLKc6RDS_zWaNLaVq3sI2YUBrKkE5qYiohvBAt6nE5ltRvwsMAmGiV7IIVBA6aec2LxxCV6F5EbWJv1MFN8hgxqsIWXkGKweUzAkw4VrNCloF-xhvDMl3DMmJ2hvJePwm-QlvUqs6M5aYo9C1Iskxo6iPpmUka5EfF1sUaWSn-viHS_o5rpmGm7hzddbFfeWWVMyx20uCLgRUoIx-RLdLrdbKmbcD6MaoomgOjNaCThwERMiEtamsJtZCTUazaZYpQWssjdPNzRp8nuSTe4Y6WgBVyTVcbsqar-bUpeLrQrdwJhaCHXxQSjXO_yG-XRQ';
const GENERATED_RUSSIA_BRIDGE_TAG_RE =
    /^(?:(?:wlrussiaejx|wlrussiagh|wlrussia|ruwl)(?:oc|vk|cv|sk|yc|ng))\d+$/;

@Injectable()
export class RootService {
    private readonly logger = new Logger(RootService.name);

    private readonly isMarzbanLegacyLinkEnabled: boolean;
    private readonly marzbanSecretKey?: string;
    private readonly bridgeOutbounds: XrayOutbound[];

    constructor(
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,
        private readonly axiosService: AxiosService,
    ) {
        this.isMarzbanLegacyLinkEnabled = this.configService.getOrThrow<boolean>(
            'MARZBAN_LEGACY_LINK_ENABLED',
        );
        this.marzbanSecretKey = this.configService.get<string>('MARZBAN_LEGACY_SECRET_KEY');
        this.bridgeOutbounds = this.extractBridgeOutboundsFromSnapshot();
    }

    public async serveSubscriptionPage(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
        clientType?: TRequestTemplateTypeKeys,
    ): Promise<void> {
        try {
            const userAgent = req.headers['user-agent'];

            let shortUuidLocal = shortUuid;

            if (this.isGenericPath(req.path)) {
                res.socket?.destroy();
                return;
            }

            if (this.isMarzbanLegacyLinkEnabled) {
                const username = await this.decodeMarzbanLink(shortUuid);

                if (username) {
                    const sanitizedUsername = sanitizeUsername(username.username);

                    this.logger.log(
                        `Decoded Marzban username: ${username.username}, sanitized username: ${sanitizedUsername}`,
                    );

                    const userInfo = await this.axiosService.getUserByUsername(
                        clientIp,
                        sanitizedUsername,
                    );
                    if (!userInfo.isOk || !userInfo.response) {
                        this.logger.error(
                            `Decoded Marzban username is not found in Remnawave, decoded username: ${sanitizedUsername}`,
                        );

                        res.socket?.destroy();
                        return;
                    }

                    shortUuidLocal = userInfo.response.response.shortUuid;
                }
            }

            if (userAgent && this.isBrowser(userAgent)) {
                return this.returnWebpage(clientIp, req, res, shortUuidLocal);
            }

            // Без /mihomo в пути, но UA mihomo/clash — запрашиваем у панели mihomo-конфиг
            const effectiveClientType: TRequestTemplateTypeKeys | undefined =
                clientType ??
                (this.isMihomoUserAgent(userAgent as string)
                    ? ('mihomo' as TRequestTemplateTypeKeys)
                    : undefined);

            let subscriptionDataResponse: {
                response: unknown;
                headers: RawAxiosResponseHeaders | AxiosResponseHeaders;
            } | null = null;

            subscriptionDataResponse = await this.axiosService.getSubscription(
                clientIp,
                shortUuidLocal,
                req.headers,
                !!effectiveClientType,
                effectiveClientType,
            );

            if (!subscriptionDataResponse) {
                res.socket?.destroy();
                return;
            }

            if (subscriptionDataResponse.headers) {
                Object.entries(subscriptionDataResponse.headers)
                    .filter(([key]) => {
                        const ignoredHeaders = ['transfer-encoding', 'content-length', 'server'];
                        return !ignoredHeaders.includes(key.toLowerCase());
                    })
                    .forEach(([key, value]) => {
                        res.setHeader(key, value);
                    });
            }

            // Модифицируем Xray JSON, если это он
            let responseData = subscriptionDataResponse.response;
            if (this.isXrayJsonResponse(responseData)) {
                responseData = this.modifyXrayJsonConfig(
                    responseData as XrayConfig[],
                    this.bridgeOutbounds,
                );

                // Удаляем заголовки кэширования, т.к. мы модифицировали данные
                res.removeHeader('etag');
                res.removeHeader('last-modified');
                res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            }

            // Модифицируем конфиг mihomo (Clash): запрос был по /mihomo или по UA (effectiveClientType уже 'mihomo')
            if (effectiveClientType === 'mihomo' && typeof responseData === 'string') {
                this.logger.log(
                    `[mihomo] shortUuid=${shortUuidLocal}, byPath=${clientType === 'mihomo'}, ua=${(userAgent as string)?.slice(0, 50)}, response length=${(responseData as string).length} chars, modifying`,
                );
                responseData = modifyMihomoConfig(responseData);
                this.logger.log(
                    `[mihomo] modified, new length=${(responseData as string).length} chars`,
                );
                res.removeHeader('etag');
                res.removeHeader('last-modified');
                res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            }

            res.status(200).send(responseData);
        } catch (error) {
            this.logger.error('Error in serveSubscriptionPage', error);

            res.socket?.destroy();
            return;
        }
    }

    private async generateJwtForCookie(): Promise<string> {
        return this.jwtService.sign(
            {
                sessionId: nanoid(32),
            },
            {
                expiresIn: '1h',
            },
        );
    }

    private isBrowser(userAgent: string): boolean {
        const browserKeywords = [
            'Mozilla',
            'Chrome',
            'Safari',
            'Firefox',
            'Opera',
            'Edge',
            'TelegramBot',
        ];

        return browserKeywords.some((keyword) => userAgent.includes(keyword));
    }

    private isGenericPath(path: string): boolean {
        const genericPaths = ['favicon.ico', 'robots.txt'];

        return genericPaths.some((genericPath) => path.includes(genericPath));
    }

    private isMihomoUserAgent(ua: string | undefined): boolean {
        if (!ua || typeof ua !== 'string') return false;
        const lower = ua.toLowerCase();
        return (
            lower.includes('mihomo') ||
            lower.includes('clash') ||
            lower.includes('stash') ||
            lower.includes('koala-clash')
        );
    }

    private isMihomoYaml(str: string): boolean {
        return (
            str.includes('proxies:') && (str.includes('mixed-port') || str.includes('proxy-groups'))
        );
    }

    private cloneXrayOutbound(outbound: XrayOutbound): XrayOutbound {
        return JSON.parse(JSON.stringify(outbound)) as XrayOutbound;
    }

    private cloneUnknown<T>(value: T): T {
        return JSON.parse(JSON.stringify(value)) as T;
    }

    private extractBridgeOutboundsFromSnapshot(): XrayOutbound[] {
        const snapshotConfigs = Array.isArray(bridgeSubscriptionSnapshot)
            ? bridgeSubscriptionSnapshot
            : [bridgeSubscriptionSnapshot];

        const bridgeOutbounds = this.extractBridgeOutbounds(snapshotConfigs as XrayConfig[]);

        if (bridgeOutbounds.length === 0) {
            this.logger.warn('Local Xray bridge snapshot has zero tp_BRIDGE outbounds');
        } else {
            this.logger.log(
                `Local Xray bridge snapshot loaded outbounds=${bridgeOutbounds.length}`,
            );
        }

        return bridgeOutbounds;
    }

    private extractBridgeOutbounds(configs: XrayConfig[]): XrayOutbound[] {
        const grouped = new Map<BridgeGroup, XrayOutbound[]>(
            BRIDGE_GROUP_ORDER.map((group) => [group, []]),
        );

        for (const config of configs) {
            for (const outbound of config.outbounds) {
                const bridgeGroup = this.getBridgeGroup(outbound.tag);
                if (!bridgeGroup) continue;

                grouped.get(bridgeGroup)!.push(outbound);
            }
        }

        const renamedOutbounds: XrayOutbound[] = [];

        for (const group of BRIDGE_GROUP_ORDER) {
            const outbounds = grouped.get(group)!;
            const tagPrefix = BRIDGE_GROUP_TO_SELECTOR[group];

            outbounds.forEach((outbound, index) => {
                const cloned = this.cloneXrayOutbound(outbound);
                cloned.tag = `${tagPrefix}${index + 1}`;
                renamedOutbounds.push(cloned);
            });
        }

        return renamedOutbounds;
    }

    private getBridgeGroup(tag: string): BridgeGroup | null {
        if (!tag.startsWith('tp_BRIDGE')) {
            return null;
        }

        const groupMatch = tag.match(/\.grp_(OC|VK|CV|SK|YC|NG)(?:\.|$)/);
        if (!groupMatch) {
            return null;
        }

        return groupMatch[1].toLowerCase() as BridgeGroup;
    }

    private async returnWebpage(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
    ): Promise<void> {
        try {
            const cookieJwt = await this.generateJwtForCookie();

            const subscriptionDataResponse = await this.axiosService.getSubscriptionInfo(
                clientIp,
                shortUuid,
            );

            if (!subscriptionDataResponse.isOk) {
                this.logger.error(`Get subscription info failed, shortUuid: ${shortUuid}`);

                res.socket?.destroy();
                return;
            }

            const subscriptionData = subscriptionDataResponse.response;

            res.cookie('session', cookieJwt, {
                httpOnly: true,
                secure: true,
                maxAge: 3_600_000, // 1 hour
            });

            res.render('index', {
                metaTitle: this.configService
                    .getOrThrow<string>('META_TITLE')
                    .replace(/^"|"$/g, ''),
                metaDescription: this.configService
                    .getOrThrow<string>('META_DESCRIPTION')
                    .replace(/^"|"$/g, ''),
                panelData: Buffer.from(JSON.stringify(subscriptionData)).toString('base64'),
            });
        } catch (error) {
            this.logger.error('Error in returnWebpage', error);

            res.socket?.destroy();
            return;
        }
    }

    private async decodeMarzbanLink(shortUuid: string): Promise<{
        username: string;
        createdAt: Date;
    } | null> {
        const token = shortUuid;
        this.logger.debug(`Verifying token: ${token}`);

        if (!token || token.length < 10) {
            this.logger.debug(`Token too short: ${token}`);
            return null;
        }

        if (token.split('.').length === 3) {
            try {
                const payload = await this.jwtService.verifyAsync(token, {
                    secret: this.marzbanSecretKey!,
                    algorithms: ['HS256'],
                });

                if (payload.access !== 'subscription') {
                    throw new Error('JWT access field is not subscription');
                }

                const jwtCreatedAt = new Date(payload.iat * 1000);

                if (!this.checkSubscriptionValidity(jwtCreatedAt, payload.sub)) {
                    return null;
                }

                this.logger.debug(`JWT verified successfully, ${JSON.stringify(payload)}`);

                return {
                    username: payload.sub,
                    createdAt: jwtCreatedAt,
                };
            } catch (err) {
                this.logger.debug(`JWT verification failed: ${err}`);
            }
        }

        const uToken = token.slice(0, token.length - 10);
        const uSignature = token.slice(token.length - 10);

        this.logger.debug(`Token parts: base: ${uToken}, signature: ${uSignature}`);

        let decoded: string;
        try {
            decoded = Buffer.from(uToken, 'base64url').toString();
        } catch (err) {
            this.logger.debug(`Base64 decode error: ${err}`);
            return null;
        }

        const hash = createHash('sha256');
        hash.update(uToken + this.marzbanSecretKey!);
        const digest = hash.digest();

        const expectedSignature = Buffer.from(digest).toString('base64url').slice(0, 10);

        this.logger.debug(`Expected signature: ${expectedSignature}, actual: ${uSignature}`);

        if (uSignature !== expectedSignature) {
            this.logger.debug('Signature mismatch');
            return null;
        }

        const parts = decoded.split(',');
        if (parts.length < 2) {
            this.logger.debug(`Invalid token format: ${decoded}`);
            return null;
        }

        const username = parts[0];
        const createdAtInt = parseInt(parts[1], 10);

        if (isNaN(createdAtInt)) {
            this.logger.debug(`Invalid created_at timestamp: ${parts[1]}`);
            return null;
        }

        const createdAt = new Date(createdAtInt * 1000);

        if (!this.checkSubscriptionValidity(createdAt, username)) {
            return null;
        }

        this.logger.debug(`Token decoded. Username: ${username}, createdAt: ${createdAt}`);

        return {
            username,
            createdAt,
        };
    }

    private checkSubscriptionValidity(createdAt: Date, username: string): boolean {
        const validFrom = this.configService.get<string | undefined>(
            'MARZBAN_LEGACY_SUBSCRIPTION_VALID_FROM',
        );

        if (!validFrom) {
            return true;
        }

        const validFromDate = new Date(validFrom);
        if (createdAt < validFromDate) {
            this.logger.debug(
                `createdAt JWT: ${createdAt.toISOString()} is before validFrom: ${validFromDate.toISOString()}`,
            );

            this.logger.warn(
                `${JSON.stringify({ username, createdAt })} – subscription createdAt is before validFrom`,
            );

            return false;
        }

        return true;
    }

    /**
     * Проверяет, является ли ответ Xray JSON конфигурацией
     */
    private isXrayJsonResponse(response: unknown): boolean {
        if (!Array.isArray(response)) {
            return false;
        }

        if (response.length === 0) {
            return false;
        }

        // Проверяем, что каждый элемент имеет remarks и outbounds
        return response.every(
            (item) =>
                typeof item === 'object' &&
                item !== null &&
                'remarks' in item &&
                'outbounds' in item &&
                Array.isArray((item as XrayConfig).outbounds),
        );
    }

    /**
     * Маппинг ISO кода страны на название
     * Стандарт ISO 3166-1 alpha-2
     */
    private readonly ISO_TO_COUNTRY: Record<string, string> = {
        PL: 'Poland',
        DE: 'Germany',
        FI: 'Finland',
        SE: 'Sweden',
        LV: 'Latvia',
        AT: 'Austria',
        US: 'USA',
        RU: 'Russia',
        NL: 'Netherlands',
        FR: 'France',
        GB: 'UK',
        JP: 'Japan',
        KR: 'Korea',
        SG: 'Singapore',
        HK: 'HongKong',
        TW: 'Taiwan',
        CA: 'Canada',
        AU: 'Australia',
        CH: 'Switzerland',
        NO: 'Norway',
        DK: 'Denmark',
        ES: 'Spain',
        IT: 'Italy',
        PT: 'Portugal',
        CZ: 'Czechia',
        RO: 'Romania',
        BG: 'Bulgaria',
        UA: 'Ukraine',
        KZ: 'Kazakhstan',
        TR: 'Turkey',
        IL: 'Israel',
        AE: 'UAE',
        IN: 'India',
        BR: 'Brazil',
        AR: 'Argentina',
        MX: 'Mexico',
        EU: 'Europe',
    };

    /**
     * Извлекает эмодзи флага из remarks (2 региональных индикатора = 1 флаг)
     */
    private extractFlagEmoji(remarks: string): string {
        const match = remarks.match(/[\u{1F1E0}-\u{1F1FF}]{2}/gu);
        return match ? match[0] : '';
    }

    /**
     * Декодирует флаг эмодзи в ISO 3166-1 alpha-2 код
     * 🇵🇱 → "PL", 🇩🇪 → "DE", 🇷🇺 → "RU"
     */
    private flagToIsoCode(flag: string): string {
        if (!flag || flag.length < 2) return '';

        const codePoints = [...flag].map((char) => char.codePointAt(0) || 0);
        const REGIONAL_A = 0x1f1e6; // Regional Indicator Symbol Letter A

        const letters = codePoints
            .filter((cp) => cp >= REGIONAL_A && cp <= 0x1f1ff)
            .map((cp) => String.fromCharCode(cp - REGIONAL_A + 65)) // 65 = 'A'
            .join('');

        return letters;
    }

    /**
     * Получает название страны по флагу
     * 🇵🇱 → "Poland", 🇩🇪 → "Germany"
     * Если страна не в маппинге — возвращает ISO код
     */
    private getCountryNameByFlag(flag: string): string {
        const isoCode = this.flagToIsoCode(flag);
        return this.ISO_TO_COUNTRY[isoCode] || isoCode;
    }

    /**
     * Создаёт tag из remarks:
     * - Убирает эмодзи, скобки, спецсимволы
     * - Оставляет только буквы и цифры
     * - lowercase
     * "🇵🇱 Poland1??" → "poland1"
     * "🇸🇪 [L7] Sweden!" → "sweden"
     */
    private createTagFromRemarks(remarks: string): string {
        const withoutEmoji = remarks.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '');
        const withoutBrackets = withoutEmoji.replace(/\[.*?\]/g, '');
        // Оставляем только буквы и цифры
        const sanitized = withoutBrackets.replace(/[^a-zA-Z0-9]/g, '');
        return sanitized.toLowerCase();
    }

    /**
     * Проверяет, является ли конфиг "Fastest" (специальный конфиг с балансировкой)
     */
    private isFastestConfig(remarks: string): boolean {
        return remarks.toLowerCase().includes('fastest');
    }

    /**
     * Проверяет, является ли страна Russia (для неё не добавляем russia outbounds)
     */
    private isRussiaByIsoCode(isoCode: string): boolean {
        return isoCode === 'RU';
    }

    /**
     * Проверяет, является ли конфиг "чистым" (remarks = флаг + название страны точно)
     * "🇵🇱 Poland" → true (чистый)
     * "🇵🇱 Poland1" → false (дочерний)
     */
    private isCleanConfig(remarks: string): boolean {
        const flag = this.extractFlagEmoji(remarks);
        if (!flag) return false;

        const countryName = this.getCountryNameByFlag(flag);
        const remarksWithoutEmoji = remarks.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();

        return remarksWithoutEmoji.toLowerCase() === countryName.toLowerCase();
    }

    /**
     * Извлекает id из proxy outbound
     * Путь: settings.vnext[0].users[0].id
     */
    private extractIdFromOutbound(outbound: XrayOutbound): string | null {
        try {
            const settings = outbound.settings as {
                vnext?: Array<{
                    users?: Array<{ id?: string }>;
                }>;
            };

            if (settings?.vnext?.[0]?.users?.[0]?.id) {
                return settings.vnext[0].users[0].id;
            }
        } catch (error) {
            this.logger.debug(`Failed to extract id from outbound: ${error}`);
        }

        return null;
    }

    /**
     * Заменяет id в outbound на новый id
     * Делает глубокую копию, чтобы не изменять исходный объект
     */
    private replaceOutboundId(outbound: XrayOutbound, newId: string): XrayOutbound {
        // Глубокая копия outbound
        const cloned = JSON.parse(JSON.stringify(outbound)) as XrayOutbound;

        try {
            const settings = cloned.settings as {
                vnext?: Array<{
                    users?: Array<{ id?: string; [key: string]: unknown }>;
                }>;
            };

            if (settings?.vnext?.[0]?.users?.[0]) {
                settings.vnext[0].users[0].id = newId;
            }
        } catch (error) {
            this.logger.debug(`Failed to replace id in outbound: ${error}`);
        }

        return cloned;
    }

    private getOutboundMux(outbound: XrayOutbound | undefined | null): unknown | undefined {
        if (!outbound || outbound.mux === undefined) {
            return undefined;
        }

        return this.cloneUnknown(outbound.mux);
    }

    private withRemnawaveMux(outbounds: XrayOutbound[], mux: unknown | undefined): XrayOutbound[] {
        return outbounds.map((outbound) => {
            const cloned = this.cloneXrayOutbound(outbound);

            if (mux !== undefined) {
                cloned.mux = this.cloneUnknown(mux);
            } else {
                delete cloned.mux;
            }

            return cloned;
        });
    }

    private extractOutboundAddress(outbound: XrayOutbound): string | null {
        try {
            const settings = outbound.settings as {
                vnext?: Array<{
                    address?: unknown;
                }>;
            };
            const address = settings?.vnext?.[0]?.address;

            return typeof address === 'string' && address.length > 0 ? address : null;
        } catch (error) {
            this.logger.debug(`Failed to extract outbound address: ${error}`);
            return null;
        }
    }

    private buildWsBridgeOutbounds(sourceOutbounds: XrayOutbound[]): XrayOutbound[] {
        const usedTags = new Set<string>();
        const wsOutbounds: XrayOutbound[] = [];

        for (const sourceOutbound of sourceOutbounds) {
            if (
                !sourceOutbound.tag ||
                sourceOutbound.tag.startsWith('ws') ||
                sourceOutbound.tag.startsWith('wlrussia')
            ) {
                continue;
            }

            const address = this.extractOutboundAddress(sourceOutbound);
            if (!address) {
                continue;
            }

            const tag = this.ensureUniqueWsTag(`ws${sourceOutbound.tag}`, usedTags);
            wsOutbounds.push({
                protocol: 'vless',
                settings: {
                    vnext: [
                        {
                            address,
                            port: WS_BRIDGE_PORT,
                            users: [
                                {
                                    encryption: WS_BRIDGE_ENCRYPTION,
                                    flow: '',
                                    id: WS_BRIDGE_ID,
                                },
                            ],
                        },
                    ],
                },
                streamSettings: {
                    network: 'ws',
                    security: 'none',
                    sockopt: {
                        dialerProxy: 'RU-DIALER',
                    },
                    wsSettings: {
                        path: '/',
                    },
                },
                tag,
            });
        }

        return wsOutbounds;
    }

    private ensureUniqueWsTag(baseTag: string, usedTags: Set<string>): string {
        if (!usedTags.has(baseTag)) {
            usedTags.add(baseTag);
            return baseTag;
        }

        let index = 2;
        while (usedTags.has(`${baseTag}_${index}`)) {
            index += 1;
        }

        const uniqueTag = `${baseTag}_${index}`;
        usedTags.add(uniqueTag);

        return uniqueTag;
    }

    private removeGeneratedBridgeOutbounds(outbounds: XrayOutbound[]): XrayOutbound[] {
        return outbounds.filter(
            (outbound) =>
                !GENERATED_RUSSIA_BRIDGE_TAG_RE.test(outbound.tag) &&
                !outbound.tag.startsWith('tp_BRIDGE'),
        );
    }

    /**
     * Модифицирует Xray JSON конфигурацию:
     * 1. Fastest: удаляет proxy, добавляет outbounds из ВСЕХ дочерних
     * 2. Чистые конфиги: удаляют proxy, получают outbounds из дочерних той же страны + russia outbounds
     * 3. Дочерние конфиги: удаляются из результата
     */
    private modifyXrayJsonConfig(
        configs: XrayConfig[],
        bridgeOutbounds: XrayOutbound[] = [],
    ): XrayConfig[] {
        // ========== Шаг 1: Классификация конфигов ==========
        let fastestConfig: XrayConfig | null = null;
        const cleanConfigs: XrayConfig[] = [];
        const childConfigs: XrayConfig[] = [];

        for (const config of configs) {
            if (this.isFastestConfig(config.remarks)) {
                fastestConfig = config;
            } else if (this.isCleanConfig(config.remarks)) {
                cleanConfigs.push(config);
            } else {
                childConfigs.push(config);
            }
        }

        if (!fastestConfig) {
            this.logger.warn('Xray JSON: "Fastest" not found, skipping modification');
            return configs;
        }

        // ========== Шаг 2: Группируем дочерние конфиги по флагу ==========
        const childByFlag = new Map<string, XrayConfig[]>();

        for (const config of childConfigs) {
            const flag = this.extractFlagEmoji(config.remarks);
            if (!flag) continue;

            if (!childByFlag.has(flag)) {
                childByFlag.set(flag, []);
            }
            childByFlag.get(flag)!.push(config);
        }

        // ========== Шаг 3: Собираем ВСЕ Russia outbounds из дочерних ==========
        const russiaFlag = '🇷🇺';
        const russiaChildConfigs = childByFlag.get(russiaFlag) || [];
        const russiaOutbounds: XrayOutbound[] = [];

        for (const config of russiaChildConfigs) {
            const proxy = config.outbounds.find((o) => o.tag === 'proxy');
            if (proxy) {
                const tag = this.createTagFromRemarks(config.remarks);
                if (tag) {
                    russiaOutbounds.push({ ...proxy, tag });
                }
            }
        }

        // ========== Шаг 4: Извлекаем id из Fastest proxy outbound ==========
        const fastestProxyOutbound = fastestConfig.outbounds.find((o) => o.tag === 'proxy');
        const fastestId = fastestProxyOutbound
            ? this.extractIdFromOutbound(fastestProxyOutbound)
            : null;
        const fastestProxyMux = this.getOutboundMux(fastestProxyOutbound);

        // ========== Шаг 5: Собираем ВСЕ proxy outbounds из дочерних для Fastest ==========
        const allChildOutbounds: XrayOutbound[] = [];

        for (const config of childConfigs) {
            const proxy = config.outbounds.find((o) => o.tag === 'proxy');
            if (proxy) {
                const tag = this.createTagFromRemarks(config.remarks);
                if (tag) {
                    let outbound: XrayOutbound = { ...proxy, tag };

                    // Заменяем id на id из Fastest только для outbounds с префиксом "wlrussia"
                    if (fastestId && tag.startsWith('wlrussia')) {
                        outbound = this.replaceOutboundId(outbound, fastestId);
                    }

                    allChildOutbounds.push(outbound);
                }
            }
        }

        // ========== Шаг 6: Модифицируем Fastest ==========
        const fastestNonProxyOutbounds = this.removeGeneratedBridgeOutbounds(
            fastestConfig.outbounds.filter((o) => o.tag !== 'proxy'),
        );
        const fastestWsOutbounds = this.buildWsBridgeOutbounds(allChildOutbounds);
        const fastestMux =
            fastestProxyMux ??
            this.getOutboundMux(allChildOutbounds.find((outbound) => outbound.mux !== undefined));
        const fastestBridgeOutbounds = this.withRemnawaveMux(bridgeOutbounds, fastestMux);
        fastestConfig.outbounds = [
            ...fastestNonProxyOutbounds,
            ...allChildOutbounds,
            ...fastestWsOutbounds,
            ...fastestBridgeOutbounds,
        ];

        // ========== Шаг 7: Модифицируем чистые конфиги ==========
        const resultConfigs: XrayConfig[] = [fastestConfig];

        for (const cleanConfig of cleanConfigs) {
            const flag = this.extractFlagEmoji(cleanConfig.remarks);
            const isoCode = this.flagToIsoCode(flag);

            // Извлекаем id из чистого конфига
            const cleanProxyOutbound = cleanConfig.outbounds.find((o) => o.tag === 'proxy');
            const cleanId = cleanProxyOutbound
                ? this.extractIdFromOutbound(cleanProxyOutbound)
                : null;
            const cleanProxyMux = this.getOutboundMux(cleanProxyOutbound);

            // Получаем дочерние конфиги этой страны
            const children = childByFlag.get(flag) || [];

            // Собираем outbounds из дочерних
            const childOutbounds: XrayOutbound[] = [];
            for (const child of children) {
                const proxy = child.outbounds.find((o) => o.tag === 'proxy');
                if (proxy) {
                    const tag = this.createTagFromRemarks(child.remarks);
                    if (tag) {
                        let outbound: XrayOutbound = { ...proxy, tag };

                        // Заменяем id на id из чистого конфига только для outbounds с префиксом "wlrussia"
                        if (cleanId && tag.startsWith('wlrussia')) {
                            outbound = this.replaceOutboundId(outbound, cleanId);
                        }

                        childOutbounds.push(outbound);
                    }
                }
            }

            // Берём все не-proxy outbounds из чистого конфига
            const nonProxyOutbounds = this.removeGeneratedBridgeOutbounds(
                cleanConfig.outbounds.filter((o) => o.tag !== 'proxy'),
            );

            // Формируем новые outbounds
            const wsOutbounds = this.buildWsBridgeOutbounds(childOutbounds);
            const newOutbounds: XrayOutbound[] = [
                ...childOutbounds,
                ...wsOutbounds,
                ...nonProxyOutbounds,
            ];

            // Добавляем ВСЕ russia outbounds (кроме самого Russia)
            if (!this.isRussiaByIsoCode(isoCode)) {
                for (const russiaOutbound of russiaOutbounds) {
                    // Клонируем Russia outbound и заменяем id
                    let clonedRussiaOutbound: XrayOutbound = JSON.parse(
                        JSON.stringify(russiaOutbound),
                    ) as XrayOutbound;

                    // Заменяем id на id из чистого конфига только для outbounds с префиксом "wlrussia"
                    if (cleanId && russiaOutbound.tag.startsWith('wlrussia')) {
                        clonedRussiaOutbound = this.replaceOutboundId(
                            clonedRussiaOutbound,
                            cleanId,
                        );
                    }

                    newOutbounds.push(clonedRussiaOutbound);
                }
            }

            const cleanMux =
                cleanProxyMux ??
                this.getOutboundMux(childOutbounds.find((outbound) => outbound.mux !== undefined));
            newOutbounds.push(...this.withRemnawaveMux(bridgeOutbounds, cleanMux));

            // Обновляем конфиг (remarks остаётся как есть)
            const modifiedConfig: XrayConfig = {
                ...cleanConfig,
                outbounds: newOutbounds,
            };

            resultConfigs.push(modifiedConfig);
        }

        this.logger.debug(
            `Xray JSON modified: ${configs.length} -> ${resultConfigs.length} configs`,
        );

        return resultConfigs;
    }
}
