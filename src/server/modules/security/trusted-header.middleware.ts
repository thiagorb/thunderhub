import { Inject, Injectable, NestMiddleware } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NextFunction, Request, Response } from 'express';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston';
import { PrincipalService } from '../principal/principal.service';
import { serializeSessionCookie, signSessionToken } from './session-cookie';
import {
  hasValidSession,
  readTrustedIdentifier,
  withAuthCookie,
} from './trusted-header';
import { TrustedProxies } from './trusted-proxy';

const appendSetCookie = (res: Response, value: string) => {
  const current = res.getHeader('Set-Cookie');
  if (!current) {
    res.setHeader('Set-Cookie', value);
    return;
  }

  const existing = Array.isArray(current)
    ? current.map(String)
    : [String(current)];
  existing.push(value);
  res.setHeader('Set-Cookie', existing);
};

/**
 * Turns the identifier a trusted reverse proxy sends (TRUSTED_AUTH_HEADER)
 * into a regular Thunderhub session. Runs before the guards, so the request
 * that arrives with only the header leaves with a cookie and is treated like
 * any other logged-in request. The header is only honoured when the socket
 * peer is one of TRUSTED_PROXY_IPS; anyone else sending it is ignored.
 */
@Injectable()
export class TrustedHeaderMiddleware implements NestMiddleware {
  private readonly headerName: string;
  private readonly proxies: TrustedProxies;

  constructor(
    private readonly configService: ConfigService,
    private readonly principalService: PrincipalService,
    @Inject(WINSTON_MODULE_PROVIDER) private readonly logger: Logger
  ) {
    this.headerName = configService.get<string>('trustedAuthHeader') || '';
    this.proxies = new TrustedProxies(
      configService.get<string[]>('trustedProxyIps') || []
    );
  }

  async use(req: Request, res: Response, next: NextFunction) {
    const headerName = this.headerName;

    if (!headerName) {
      next();
      return;
    }

    try {
      const jwtSecret = this.configService.get<string>('jwtSecret') || '';
      const cookieHeader = Array.isArray(req.headers.cookie)
        ? req.headers.cookie.join('; ')
        : req.headers.cookie;

      if (hasValidSession(cookieHeader, jwtSecret)) {
        next();
        return;
      }

      const identifier = readTrustedIdentifier(req.headers, headerName);
      if (!identifier) {
        next();
        return;
      }

      // The socket peer, never a forwarded header: only the proxy itself
      // may assert who the user is.
      const remoteAddress = req.socket?.remoteAddress;
      if (!this.proxies.allows(remoteAddress)) {
        this.logger.warn(
          `Ignoring trusted header from untrusted address ${remoteAddress || 'unknown'}`
        );
        next();
        return;
      }

      const principal =
        await this.principalService.fromTrustedIdentifier(identifier);

      if (!principal) {
        this.logger.debug(
          `Trusted header identifier "${identifier}" does not match a user`
        );
        next();
        return;
      }

      const token = signSessionToken(principal, jwtSecret);
      const useHttps = !!this.configService.get<boolean>('useHttps');

      req.headers.cookie = withAuthCookie(cookieHeader, token);
      appendSetCookie(res, serializeSessionCookie(token, useHttps));

      this.logger.info(
        `Trusted header session created for ${this.principalService.toSubject(principal)}`
      );
    } catch (error) {
      this.logger.error('Trusted header authentication failed', { error });
    }

    next();
  }
}
