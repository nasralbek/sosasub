import { RawAxiosResponseHeaders } from 'axios';
import { AxiosResponseHeaders } from 'axios';
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

@Injectable()
export class RootService {
    private readonly logger = new Logger(RootService.name);

    private readonly isMarzbanLegacyLinkEnabled: boolean;
    private readonly marzbanSecretKey?: string;

    constructor(
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService,
        private readonly axiosService: AxiosService,
    ) {
        this.isMarzbanLegacyLinkEnabled = this.configService.getOrThrow<boolean>(
            'MARZBAN_LEGACY_LINK_ENABLED',
        );
        this.marzbanSecretKey = this.configService.get<string>('MARZBAN_LEGACY_SECRET_KEY');
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

            let subscriptionDataResponse: {
                response: unknown;
                headers: RawAxiosResponseHeaders | AxiosResponseHeaders;
            } | null = null;

            subscriptionDataResponse = await this.axiosService.getSubscription(
                clientIp,
                shortUuidLocal,
                req.headers,
                !!clientType,
                clientType,
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
                responseData = this.modifyXrayJsonConfig(responseData as XrayConfig[]);
                
                // Удаляем заголовки кэширования, т.к. мы модифицировали данные
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

    /**
     * Модифицирует Xray JSON конфигурацию:
     * 1. Fastest: удаляет proxy, добавляет outbounds из ВСЕХ дочерних
     * 2. Чистые конфиги: удаляют proxy, получают outbounds из дочерних той же страны + russia outbounds
     * 3. Дочерние конфиги: удаляются из результата
     */
    private modifyXrayJsonConfig(configs: XrayConfig[]): XrayConfig[] {
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
        const fastestNonProxyOutbounds = fastestConfig.outbounds.filter((o) => o.tag !== 'proxy');
        fastestConfig.outbounds = [...fastestNonProxyOutbounds, ...allChildOutbounds];

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
            const nonProxyOutbounds = cleanConfig.outbounds.filter((o) => o.tag !== 'proxy');

            // Формируем новые outbounds
            const newOutbounds: XrayOutbound[] = [...childOutbounds, ...nonProxyOutbounds];

            // Добавляем ВСЕ russia outbounds (кроме самого Russia)
            if (!this.isRussiaByIsoCode(isoCode)) {
                for (const russiaOutbound of russiaOutbounds) {
                    // Клонируем Russia outbound и заменяем id
                    let clonedRussiaOutbound: XrayOutbound = JSON.parse(
                        JSON.stringify(russiaOutbound),
                    ) as XrayOutbound;

                    // Заменяем id на id из чистого конфига только для outbounds с префиксом "wlrussia"
                    if (cleanId && russiaOutbound.tag.startsWith('wlrussia')) {
                        clonedRussiaOutbound = this.replaceOutboundId(clonedRussiaOutbound, cleanId);
                    }

                    newOutbounds.push(clonedRussiaOutbound);
                }
            }

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

