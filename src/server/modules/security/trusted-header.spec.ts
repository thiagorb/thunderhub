import jwt from 'jsonwebtoken';
import { AuthType, parseSubject } from './security.types';
import { signSessionToken } from './session-cookie';
import {
  hasValidSession,
  readAuthToken,
  readTrustedIdentifier,
  withAuthCookie,
} from './trusted-header';
import { TrustedHeaderMiddleware } from './trusted-header.middleware';

const secret = 'test-secret';

describe('readTrustedIdentifier', () => {
  it('reads and trims the configured header, case-insensitively', () => {
    expect(
      readTrustedIdentifier(
        { 'x-authentik-email': ' You@Example.com ' },
        'X-Authentik-Email'
      )
    ).toBe('You@Example.com');
  });

  it('accepts identifiers that are not emails', () => {
    expect(
      readTrustedIdentifier({ 'remote-user': 'alice' }, 'remote-user')
    ).toBe('alice');
  });

  it('rejects missing, blank, or whitespace-containing values', () => {
    expect(readTrustedIdentifier({}, 'remote-user')).toBe('');
    expect(readTrustedIdentifier({ 'remote-user': '  ' }, 'remote-user')).toBe(
      ''
    );
    expect(
      readTrustedIdentifier({ 'remote-user': 'two words' }, 'remote-user')
    ).toBe('');
    expect(readTrustedIdentifier({ 'remote-user': 'x' }, '')).toBe('');
  });
});

describe('cookie helpers', () => {
  it('reads the auth cookie out of a cookie header', () => {
    expect(readAuthToken('theme=dark; Thub-Auth=abc; other=1')).toBe('abc');
    expect(readAuthToken('theme=dark')).toBe('');
  });

  it('replaces an existing auth cookie and keeps the others', () => {
    expect(withAuthCookie('theme=dark; Thub-Auth=old', 'new')).toBe(
      'theme=dark; Thub-Auth=new'
    );
    expect(withAuthCookie(undefined, 'new')).toBe('Thub-Auth=new');
  });

  it('accepts a signed session and rejects an expired one', () => {
    const valid = signSessionToken({ type: AuthType.USER, id: 'u1' }, secret);
    expect(hasValidSession(`Thub-Auth=${valid}`, secret)).toBe(true);

    const expired = jwt.sign(
      { sub: 'user:1', exp: Math.floor(Date.now() / 1000) - 10 },
      secret,
      { algorithm: 'HS256' }
    );
    expect(hasValidSession(`Thub-Auth=${expired}`, secret)).toBe(false);
    expect(hasValidSession(`Thub-Auth=${valid}`, 'other')).toBe(false);
  });
});

describe('TrustedHeaderMiddleware', () => {
  const makeConfig = (headerName: string) => ({
    get: (key: string) =>
      (
        ({
          trustedAuthHeader: headerName,
          jwtSecret: secret,
          useHttps: false,
        }) as Record<string, string | boolean>
      )[key],
  });

  const logger = { info: jest.fn(), debug: jest.fn(), error: jest.fn() };

  const makeRes = () => {
    const headers: Record<string, string | string[]> = {};
    return {
      headers,
      res: {
        getHeader: (name: string) => headers[name.toLowerCase()],
        setHeader: (name: string, value: string | string[]) => {
          headers[name.toLowerCase()] = value;
        },
      } as any,
    };
  };

  const sessionSubject = (cookie: string) =>
    parseSubject(
      (jwt.verify(cookie.replace('Thub-Auth=', ''), secret) as { sub: string })
        .sub
    );

  it('does nothing when no header is configured', async () => {
    const principalService = { fromTrustedIdentifier: jest.fn() };
    const middleware = new TrustedHeaderMiddleware(
      makeConfig('') as any,
      principalService as any,
      logger as any
    );
    const req = { headers: { 'x-authentik-email': 'a@example.com' } } as any;
    const next = jest.fn();

    await middleware.use(req, makeRes().res, next);

    expect(next).toHaveBeenCalled();
    expect(req.headers.cookie).toBeUndefined();
    expect(principalService.fromTrustedIdentifier).not.toHaveBeenCalled();
  });

  it('creates a session for the resolved principal', async () => {
    const principalService = {
      fromTrustedIdentifier: jest
        .fn()
        .mockResolvedValue({ type: AuthType.YAML_USER, id: 'a@example.com' }),
      toSubject: () => 'yaml-user:a@example.com',
    };
    const middleware = new TrustedHeaderMiddleware(
      makeConfig('X-Authentik-Email') as any,
      principalService as any,
      logger as any
    );
    const req = { headers: { 'x-authentik-email': 'A@Example.com' } } as any;
    const { res, headers } = makeRes();
    const next = jest.fn();

    await middleware.use(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(principalService.fromTrustedIdentifier).toHaveBeenCalledWith(
      'A@Example.com'
    );
    expect(sessionSubject(req.headers.cookie)).toEqual({
      type: AuthType.YAML_USER,
      id: 'a@example.com',
    });
    expect(String(headers['set-cookie'])).toContain('Thub-Auth=');
    expect(String(headers['set-cookie'])).toContain('HttpOnly');
  });

  it('leaves an existing valid session alone', async () => {
    const principalService = { fromTrustedIdentifier: jest.fn() };
    const middleware = new TrustedHeaderMiddleware(
      makeConfig('x-authentik-email') as any,
      principalService as any,
      logger as any
    );
    const existing = signSessionToken(
      { type: AuthType.YAML, id: 'account' },
      secret
    );
    const req = {
      headers: {
        'x-authentik-email': 'a@example.com',
        cookie: `Thub-Auth=${existing}`,
      },
    } as any;
    const { res, headers } = makeRes();

    await middleware.use(req, res, jest.fn());

    expect(principalService.fromTrustedIdentifier).not.toHaveBeenCalled();
    expect(req.headers.cookie).toBe(`Thub-Auth=${existing}`);
    expect(headers['set-cookie']).toBeUndefined();
  });

  it('does nothing when the identifier is unknown', async () => {
    const principalService = {
      fromTrustedIdentifier: jest.fn().mockResolvedValue(null),
    };
    const middleware = new TrustedHeaderMiddleware(
      makeConfig('x-authentik-email') as any,
      principalService as any,
      logger as any
    );
    const req = {
      headers: { 'x-authentik-email': 'nobody@example.com' },
    } as any;
    const { res, headers } = makeRes();
    const next = jest.fn();

    await middleware.use(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.headers.cookie).toBeUndefined();
    expect(headers['set-cookie']).toBeUndefined();
  });
});
