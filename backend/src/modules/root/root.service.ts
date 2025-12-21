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
     * Извлекает название локации из remarks
     * "🇵🇱 Poland" → "poland"
     * "🇸🇪 [L7] Sweden " → "sweden"
     */
    private extractLocationFromRemarks(remarks: string): string {
        // Удаляем эмодзи флагов (региональные индикаторы Unicode)
        const withoutEmoji = remarks.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '');

        // Удаляем квадратные скобки с содержимым [L7], [US] и т.д.
        const withoutBrackets = withoutEmoji.replace(/\[.*?\]/g, '');

        // Берем последнее слово, убираем пробелы и приводим к lowercase
        const words = withoutBrackets.trim().split(/\s+/);
        const lastWord = words[words.length - 1] || '';

        return lastWord.toLowerCase();
    }

    /**
     * Модифицирует Xray JSON конфигурацию:
     * - Находит конфиг "Fastest" и удаляет из него outbound с tag="proxy"
     * - Из ВСЕХ других конфигов берет proxy outbound, переименовывает tag в название локации и добавляет в Fastest
     * - Добавляет outbound "russia" во все конфиги кроме Fastest, Russia, USA
     */
    private modifyXrayJsonConfig(configs: XrayConfig[]): XrayConfig[] {
        this.logger.log(`Xray JSON: начинаем модификацию, всего конфигов: ${configs.length}`);
        
        // Логируем все remarks
        configs.forEach((c, i) => {
            this.logger.log(`Xray JSON: [${i}] remarks="${c.remarks}"`);
        });

        // Находим индекс конфига Fastest
        const fastestIndex = configs.findIndex((config) =>
            config.remarks.toLowerCase().includes('fastest'),
        );

        if (fastestIndex === -1) {
            this.logger.warn('Xray JSON: конфиг "Fastest" не найден, пропускаем модификацию');
            return configs;
        }

        this.logger.log(`Xray JSON: найден Fastest на индексе ${fastestIndex}`);

        // Находим конфиг Russia и его proxy outbound для добавления в другие конфиги
        const russiaConfig = configs.find((config) =>
            config.remarks.toLowerCase().includes('russia'),
        );

        let russiaOutbound: XrayOutbound | null = null;
        if (russiaConfig) {
            this.logger.log(`Xray JSON: найден конфиг Russia: "${russiaConfig.remarks}"`);
            const proxyOutbound = russiaConfig.outbounds.find(
                (outbound) => outbound.tag === 'proxy',
            );
            if (proxyOutbound) {
                russiaOutbound = {
                    ...proxyOutbound,
                    tag: 'russia',
                };
                this.logger.log('Xray JSON: russiaOutbound создан');
            } else {
                this.logger.warn('Xray JSON: в конфиге Russia не найден proxy outbound!');
            }
        } else {
            this.logger.warn('Xray JSON: конфиг Russia не найден!');
        }

        const fastestConfig = configs[fastestIndex];

        // Удаляем proxy outbound из Fastest
        const fastestOutboundsWithoutProxy = fastestConfig.outbounds.filter(
            (outbound) => outbound.tag !== 'proxy',
        );

        // Собираем proxy outbounds из ВСЕХ других конфигов для Fastest
        const additionalOutbounds: XrayOutbound[] = [];

        for (let i = 0; i < configs.length; i++) {
            if (i === fastestIndex) {
                continue; // Пропускаем Fastest
            }

            const config = configs[i];
            const remarks = config.remarks.toLowerCase();
            const isUsaOrRussia = remarks.includes('usa') || remarks.includes('russia');

            // Находим proxy outbound
            const proxyOutbound = config.outbounds.find((outbound) => outbound.tag === 'proxy');

            if (proxyOutbound) {
                // Извлекаем название локации из remarks
                const locationTag = this.extractLocationFromRemarks(config.remarks);
                this.logger.log(`Xray JSON: [${i}] "${config.remarks}" -> tag="${locationTag}"`);

                if (locationTag) {
                    // Клонируем outbound и меняем tag — добавляем в Fastest
                    const modifiedOutbound: XrayOutbound = {
                        ...proxyOutbound,
                        tag: locationTag,
                    };

                    additionalOutbounds.push(modifiedOutbound);
                } else {
                    this.logger.warn(`Xray JSON: [${i}] пустой locationTag для "${config.remarks}"`);
                }
            } else {
                this.logger.warn(`Xray JSON: [${i}] "${config.remarks}" - нет proxy outbound`);
            }

            // Добавляем outbound russia в конфиги (кроме USA и Russia)
            if (!isUsaOrRussia && russiaOutbound) {
                const hasRussiaOutbound = config.outbounds.some(
                    (outbound) => outbound.tag === 'russia',
                );
                if (!hasRussiaOutbound) {
                    config.outbounds.push({ ...russiaOutbound });
                    this.logger.log(`Xray JSON: [${i}] добавлен russia outbound`);
                }
            }
        }

        // Обновляем outbounds в Fastest:
        // сначала существующие (без proxy), затем добавленные из других конфигов
        fastestConfig.outbounds = [...fastestOutboundsWithoutProxy, ...additionalOutbounds];

        this.logger.log(
            `Xray JSON: модифицирован Fastest, добавлено ${additionalOutbounds.length} outbounds: ${additionalOutbounds.map((o) => o.tag).join(', ')}`,
        );

        return configs;
    }
}
