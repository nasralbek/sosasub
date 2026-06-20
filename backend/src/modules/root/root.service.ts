import { Request, Response } from 'express';
import { createHash } from 'node:crypto';
import { nanoid } from 'nanoid';

import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Logger } from '@nestjs/common';

import { TRequestTemplateTypeKeys } from '@remnawave/backend-contract';

import { TypedConfigService } from '@common/config/app-config';
import { AxiosService } from '@common/axios/axios.service';
import { IGNORED_HEADERS } from '@common/constants';
import { sanitizeUsername } from '@common/utils';

import { SubpageConfigService } from './subpage-config.service';

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
    private readonly marzbanSecretKeys: string[];
    private readonly mlDropRevokedSubscriptions: boolean;
    constructor(
        private readonly configService: TypedConfigService,
        private readonly jwtService: JwtService,
        private readonly axiosService: AxiosService,
        private readonly subpageConfigService: SubpageConfigService,
    ) {
        this.isMarzbanLegacyLinkEnabled = this.configService.getOrThrow(
            'MARZBAN_LEGACY_LINK_ENABLED',
        );
        this.mlDropRevokedSubscriptions = this.configService.getOrThrow(
            'MARZBAN_LEGACY_DROP_REVOKED_SUBSCRIPTIONS',
        );

        const marzbanSecretKeys = this.configService.get('MARZBAN_LEGACY_SECRET_KEY');

        if (marzbanSecretKeys && marzbanSecretKeys.length > 0) {
            this.marzbanSecretKeys = marzbanSecretKeys.split(',').map((key) => key.trim());
        } else {
            this.marzbanSecretKeys = [];
        }
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
                const username = await this.tryDecodeMarzbanLink(shortUuid);

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
                    } else if (
                        this.mlDropRevokedSubscriptions &&
                        userInfo.response.response.subRevokedAt !== null
                    ) {
                        res.socket?.destroy();
                        return;
                    }

                    shortUuidLocal = userInfo.response.response.shortUuid;
                }
            }

            if (userAgent && this.isBrowser(userAgent)) {
                return this.returnWebpage(clientIp, req, res, shortUuidLocal);
            }

            const subscriptionDataResponse = await this.axiosService.getSubscription(
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
                    .filter(([key]) => !IGNORED_HEADERS.has(key.toLowerCase()))
                    .forEach(([key, value]) => {
                        res.setHeader(key, value);
                    });
            }

            let responseData = subscriptionDataResponse.response;
            if (this.isXrayJsonResponse(responseData)) {
                responseData = this.modifyXrayJsonConfig(responseData as XrayConfig[]);

                res.removeHeader('etag');
                res.removeHeader('last-modified');
                res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            }

            res.status(200).send(responseData);
            return;
        } catch (error) {
            this.logger.error('Error in serveSubscriptionPage', error);

            res.socket?.destroy();
            return;
        }
    }

    private generateJwtForCookie(uuid: string | null): string {
        return this.jwtService.sign(
            {
                sessionId: nanoid(32),
                su: this.subpageConfigService.getEncryptedSubpageConfigUuid(uuid),
            },
            {
                expiresIn: '33m',
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
            'WhatsApp',
        ];

        return browserKeywords.some((keyword) => userAgent.includes(keyword));
    }

    private isGenericPath(path: string): boolean {
        const genericPaths = [
            'favicon.ico',
            'robots.txt',
            '.png',
            '.jpg',
            '.jpeg',
            '.gif',
            '.svg',
            '.webp',
            '.ico',
        ];

        return genericPaths.some((genericPath) => path.includes(genericPath));
    }

    private async returnWebpage(
        clientIp: string,
        req: Request,
        res: Response,
        shortUuid: string,
    ): Promise<void> {
        try {
            const subscriptionDataResponse = await this.axiosService.getSubscriptionInfo(
                clientIp,
                shortUuid,
            );

            if (!subscriptionDataResponse.isOk || !subscriptionDataResponse.response) {
                res.socket?.destroy();
                return;
            }

            const subpageConfigResponse = await this.axiosService.getSubpageConfig(
                shortUuid,
                req.headers,
            );

            if (!subpageConfigResponse.isOk || !subpageConfigResponse.response) {
                res.socket?.destroy();
                return;
            }

            const subpageConfig = subpageConfigResponse.response;

            if (subpageConfig.webpageAllowed === false) {
                this.logger.log(`Webpage access is not allowed by Remnawave's SRR.`);
                res.socket?.destroy();
                return;
            }

            const baseSettings = this.subpageConfigService.getBaseSettings(
                subpageConfig.subpageConfigUuid,
            );

            const subscriptionData = subscriptionDataResponse.response;

            if (!baseSettings.showConnectionKeys) {
                subscriptionData.response.links = [];
                subscriptionData.response.ssConfLinks = {};
            }

            res.cookie('session', this.generateJwtForCookie(subpageConfig.subpageConfigUuid), {
                httpOnly: true,
                secure: true,
                maxAge: 1_800_000, // 30 minutes
            });

            res.render('index', {
                metaTitle: baseSettings.metaTitle,
                metaDescription: baseSettings.metaDescription,
                panelData: Buffer.from(JSON.stringify(subscriptionData)).toString('base64'),
            });
        } catch (error) {
            this.logger.error(`Error in returnWebpage: ${error}`);

            res.socket?.destroy();
            return;
        }
    }

    private async tryDecodeMarzbanLink(shortUuid: string): Promise<{
        username: string;
        createdAt: Date;
    } | null> {
        if (!this.marzbanSecretKeys.length) return null;

        const token = shortUuid;
        this.logger.debug(`Verifying token: ${token}`);

        if (!token || token.length < 10) {
            this.logger.debug(`Token too short: ${token}`);
            return null;
        }

        for (const key of this.marzbanSecretKeys) {
            const result = await this.decodeMarzbanLink(shortUuid, key);
            if (result) return result;

            this.logger.debug(`Decoding Marzban link failed with key: ${key}`);
        }

        this.logger.debug(`Decoding Marzban link failed with all keys`);

        return null;
    }

    private async decodeMarzbanLink(
        token: string,
        marzbanSecretKey: string,
    ): Promise<{
        username: string;
        createdAt: Date;
    } | null> {
        if (token.split('.').length === 3) {
            try {
                const payload = await this.jwtService.verifyAsync(token, {
                    secret: marzbanSecretKey,
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
        hash.update(uToken + marzbanSecretKey);
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
        const validFrom = this.configService.get('MARZBAN_LEGACY_SUBSCRIPTION_VALID_FROM');

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

    private isXrayJsonResponse(response: unknown): boolean {
        if (!Array.isArray(response) || response.length === 0) {
            return false;
        }

        return response.every(
            (item) =>
                typeof item === 'object' &&
                item !== null &&
                'remarks' in item &&
                'outbounds' in item &&
                Array.isArray((item as XrayConfig).outbounds),
        );
    }

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

    private extractFlagEmoji(remarks: string): string {
        const match = remarks.match(/[\u{1F1E0}-\u{1F1FF}]{2}/gu);
        return match ? match[0] : '';
    }

    private flagToIsoCode(flag: string): string {
        if (!flag || flag.length < 2) return '';

        const codePoints = [...flag].map((char) => char.codePointAt(0) || 0);
        const regionalA = 0x1f1e6;

        return codePoints
            .filter((codePoint) => codePoint >= regionalA && codePoint <= 0x1f1ff)
            .map((codePoint) => String.fromCharCode(codePoint - regionalA + 65))
            .join('');
    }

    private getCountryNameByFlag(flag: string): string {
        const isoCode = this.flagToIsoCode(flag);
        return this.ISO_TO_COUNTRY[isoCode] || isoCode;
    }

    private createTagFromRemarks(remarks: string): string {
        const withoutEmoji = remarks.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '');
        const withoutBrackets = withoutEmoji.replace(/\[.*?\]/g, '');
        return withoutBrackets.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
    }

    private isFastestConfig(remarks: string): boolean {
        return remarks.toLowerCase().includes('fastest');
    }

    private isRussiaByIsoCode(isoCode: string): boolean {
        return isoCode === 'RU';
    }

    private isCleanConfig(remarks: string): boolean {
        const flag = this.extractFlagEmoji(remarks);
        if (!flag) return false;

        const countryName = this.getCountryNameByFlag(flag);
        const remarksWithoutEmoji = remarks.replace(/[\u{1F1E0}-\u{1F1FF}]/gu, '').trim();

        return remarksWithoutEmoji.toLowerCase() === countryName.toLowerCase();
    }

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

    private replaceOutboundId(outbound: XrayOutbound, newId: string): XrayOutbound {
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

            const streamSettings = cloned.streamSettings as {
                hysteriaSettings?: { auth?: string; [key: string]: unknown };
            };

            if (streamSettings?.hysteriaSettings?.auth) {
                streamSettings.hysteriaSettings.auth = newId;
            }
        } catch (error) {
            this.logger.debug(`Failed to replace id in outbound: ${error}`);
        }

        return cloned;
    }

    private modifyXrayJsonConfig(configs: XrayConfig[]): XrayConfig[] {
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

        const childByFlag = new Map<string, XrayConfig[]>();

        for (const config of childConfigs) {
            const flag = this.extractFlagEmoji(config.remarks);
            if (!flag) continue;

            if (!childByFlag.has(flag)) {
                childByFlag.set(flag, []);
            }
            childByFlag.get(flag)!.push(config);
        }

        const russiaFlag = String.fromCodePoint(0x1f1f7, 0x1f1fa);
        const russiaChildConfigs = childByFlag.get(russiaFlag) || [];
        const russiaOutbounds: XrayOutbound[] = [];

        for (const config of russiaChildConfigs) {
            const proxy = config.outbounds.find((outbound) => outbound.tag === 'proxy');
            if (!proxy) continue;

            const tag = this.createTagFromRemarks(config.remarks);
            if (tag) {
                russiaOutbounds.push({ ...proxy, tag });
            }
        }

        const fastestProxyOutbound = fastestConfig.outbounds.find(
            (outbound) => outbound.tag === 'proxy',
        );
        const fastestId = fastestProxyOutbound
            ? this.extractIdFromOutbound(fastestProxyOutbound)
            : null;

        const allChildOutbounds: XrayOutbound[] = [];

        for (const config of childConfigs) {
            const proxy = config.outbounds.find((outbound) => outbound.tag === 'proxy');
            if (!proxy) continue;

            const tag = this.createTagFromRemarks(config.remarks);
            if (!tag) continue;

            let outbound: XrayOutbound = { ...proxy, tag };

            if (fastestId && tag.startsWith('wlrussia')) {
                outbound = this.replaceOutboundId(outbound, fastestId);
            }

            allChildOutbounds.push(outbound);
        }

        const fastestNonProxyOutbounds = fastestConfig.outbounds.filter(
            (outbound) => outbound.tag !== 'proxy',
        );
        fastestConfig.outbounds = [...fastestNonProxyOutbounds, ...allChildOutbounds];

        const resultConfigs: XrayConfig[] = [fastestConfig];

        for (const cleanConfig of cleanConfigs) {
            const flag = this.extractFlagEmoji(cleanConfig.remarks);
            const isoCode = this.flagToIsoCode(flag);
            const cleanProxyOutbound = cleanConfig.outbounds.find(
                (outbound) => outbound.tag === 'proxy',
            );
            const cleanId = cleanProxyOutbound
                ? this.extractIdFromOutbound(cleanProxyOutbound)
                : null;
            const children = childByFlag.get(flag) || [];
            const childOutbounds: XrayOutbound[] = [];

            for (const child of children) {
                const proxy = child.outbounds.find((outbound) => outbound.tag === 'proxy');
                if (!proxy) continue;

                const tag = this.createTagFromRemarks(child.remarks);
                if (!tag) continue;

                let outbound: XrayOutbound = { ...proxy, tag };

                if (cleanId && tag.startsWith('wlrussia')) {
                    outbound = this.replaceOutboundId(outbound, cleanId);
                }

                childOutbounds.push(outbound);
            }

            const nonProxyOutbounds = cleanConfig.outbounds.filter(
                (outbound) => outbound.tag !== 'proxy',
            );
            const newOutbounds: XrayOutbound[] = [...childOutbounds, ...nonProxyOutbounds];

            if (!this.isRussiaByIsoCode(isoCode)) {
                for (const russiaOutbound of russiaOutbounds) {
                    let clonedRussiaOutbound = JSON.parse(
                        JSON.stringify(russiaOutbound),
                    ) as XrayOutbound;

                    if (cleanId && russiaOutbound.tag.startsWith('wlrussia')) {
                        clonedRussiaOutbound = this.replaceOutboundId(
                            clonedRussiaOutbound,
                            cleanId,
                        );
                    }

                    newOutbounds.push(clonedRussiaOutbound);
                }
            }

            resultConfigs.push({
                ...cleanConfig,
                outbounds: newOutbounds,
            });
        }

        this.logger.debug(
            `Xray JSON modified: ${configs.length} -> ${resultConfigs.length} configs`,
        );

        return resultConfigs;
    }
}
