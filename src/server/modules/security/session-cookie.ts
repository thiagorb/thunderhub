import jwt from 'jsonwebtoken';
import * as cookieLib from 'cookie';
import { appConstants } from '../../utils/appConstants';
import { Principal } from '../principal/principal.types';
import { toSubject } from './security.types';

export const SESSION_TTL = '24h';

/** Signs the session JWT every login path stores in the `Thub-Auth` cookie. */
export function signSessionToken(principal: Principal, secret: string): string {
  return jwt.sign({ sub: toSubject(principal) }, secret, {
    algorithm: 'HS256',
    expiresIn: SESSION_TTL,
  });
}

export function serializeSessionCookie(
  token: string,
  useHttps: boolean
): string {
  return cookieLib.serialize(appConstants.cookieName, token, {
    httpOnly: true,
    sameSite: true,
    path: '/',
    secure: useHttps,
  });
}
