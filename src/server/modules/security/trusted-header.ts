import jwt from 'jsonwebtoken';
import { appConstants } from '../../utils/appConstants';

const MAX_IDENTIFIER_LENGTH = 254;

export type IncomingHeaders = Record<string, string | string[] | undefined>;

/** The identifier a trusted proxy placed in `headerName`, or '' if unusable. */
export function readTrustedIdentifier(
  headers: IncomingHeaders,
  headerName: string
): string {
  if (!headerName) return '';

  const raw = headers[headerName.toLowerCase()];
  const value = (Array.isArray(raw) ? raw[0] : raw) || '';
  const trimmed = value.trim();

  if (
    !trimmed ||
    trimmed.length > MAX_IDENTIFIER_LENGTH ||
    /\s/.test(trimmed)
  ) {
    return '';
  }

  return trimmed;
}

export function readAuthToken(cookieHeader?: string): string {
  if (!cookieHeader) return '';

  const prefix = `${appConstants.cookieName}=`;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    if (!trimmed.startsWith(prefix)) continue;

    try {
      return decodeURIComponent(trimmed.slice(prefix.length));
    } catch {
      return '';
    }
  }

  return '';
}

/** Rewrites the request cookie header so this request already carries the session. */
export function withAuthCookie(
  cookieHeader: string | undefined,
  token: string
): string {
  const pair = `${appConstants.cookieName}=${token}`;
  if (!cookieHeader) return pair;

  const kept = cookieHeader
    .split(';')
    .map(part => part.trim())
    .filter(part => part && !part.startsWith(`${appConstants.cookieName}=`));

  kept.push(pair);
  return kept.join('; ');
}

export function hasValidSession(
  cookieHeader: string | undefined,
  jwtSecret: string
): boolean {
  const token = readAuthToken(cookieHeader);
  if (!token || !jwtSecret) return false;

  try {
    const payload = jwt.verify(token, jwtSecret) as { sub?: string };
    return typeof payload?.sub === 'string' && payload.sub.length > 0;
  } catch {
    return false;
  }
}
