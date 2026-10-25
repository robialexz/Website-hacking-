export type LabProfile = 'vulnerable' | 'secure';

export interface LabState {
  /** Records which authenticated users have already used the demo coupon. */
  redeemedCoupons: Set<string>;
}

export interface LabRequest {
  method: string;
  url: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface LabResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

type LabIdentity = {
  userId: string;
  role: 'user' | 'admin';
};

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const HTML_CONTENT_TYPE = 'text/html; charset=utf-8';

const RECORDS: Readonly<Record<string, Readonly<Record<string, unknown>>>> = {
  '1': { ownerUserId: '1', name: 'Alice Example', recordId: 'RG-REC-001', plan: 'Synthetic Basic' },
  '2': { ownerUserId: '2', name: 'Bob Example', recordId: 'RG-REC-002', plan: 'Synthetic Plus' },
};

const SEARCH_ITEMS = [
  { id: 'item-1', name: 'Blue widget', category: 'synthetic tools' },
  { id: 'item-2', name: 'Green widget', category: 'synthetic tools' },
  { id: 'item-3', name: 'Copper cable', category: 'synthetic supplies' },
] as const;

// This is a virtual fixture. The file route never accesses the host filesystem.
const VIRTUAL_FILES: Readonly<Record<string, string>> = {
  'public/readme.txt': 'Synthetic public lab readme.',
  'private/lab-secret.txt': 'Synthetic lab secret: RG_LAB_FILE_MARKER.',
};

const DEPENDENCIES = {
  synthetic: true,
  dependencies: [
    {
      name: 'synthetic-example-package',
      version: '0.0.1',
      source: 'fictional fixture only',
      advisory: 'RG-DEMO-001',
      requiresLiveValidation: true,
    },
  ],
};

export function createLabState(): LabState {
  return { redeemedCoupons: new Set<string>() };
}

export function resetLabState(state: LabState): void {
  state.redeemedCoupons.clear();
}

export function handleLabRequest(
  request: LabRequest,
  profile: LabProfile,
  state: LabState,
): LabResponse {
  let url: URL;
  try {
    // URL is used only as a parser; this handler performs no network requests.
    url = new URL(request.url, 'http://lab.local');
  } catch {
    return jsonResponse(400, { error: 'Invalid URL' });
  }

  const method = request.method.toUpperCase();
  const headers = normalizeHeaders(request.headers ?? {});

  switch (url.pathname) {
    case '/lab/api/records': {
      if (method !== 'GET') return methodNotAllowed();
      const identity = getIdentity(headers);
      if (!identity) return jsonResponse(401, { error: 'Authentication required' });

      const userId = url.searchParams.get('user_id');
      if (!userId || !/^\d+$/.test(userId)) {
        return jsonResponse(400, { error: 'A numeric user_id is required' });
      }

      const record = RECORDS[userId];
      if (!record) return jsonResponse(404, { error: 'Record not found' });
      if (profile === 'secure' && identity.role !== 'admin' && identity.userId !== userId) {
        return jsonResponse(403, { error: 'Record access denied' });
      }
      return jsonResponse(200, { record });
    }

    case '/lab/api/admin': {
      if (method !== 'GET') return methodNotAllowed();
      if (profile === 'secure') {
        const identity = getIdentity(headers);
        if (!identity) return jsonResponse(401, { error: 'Authentication required' });
        if (identity.role !== 'admin') return jsonResponse(403, { error: 'Admin role required' });
      }
      return jsonResponse(200, {
        panel: 'synthetic-admin',
        synthetic: true,
        recordCount: Object.keys(RECORDS).length,
      });
    }

    case '/lab/api/search': {
      if (method !== 'GET') return methodNotAllowed();
      const query = url.searchParams.get('q') ?? '';
      // Harmless canary standing in for an unsafe query branch. No SQL is run.
      const results = profile === 'vulnerable' && query.includes('LAB_SEARCH_ALL')
        ? [...SEARCH_ITEMS]
        : SEARCH_ITEMS.filter(item => `${item.name} ${item.category}`.toLowerCase().includes(query.toLowerCase()));
      return jsonResponse(200, { results });
    }

    case '/lab/api/comment': {
      if (method !== 'GET') return methodNotAllowed();
      const comment = url.searchParams.get('q') ?? '';
      // The only active marker is fixed; arbitrary query input is never copied into HTML.
      const reflected = profile === 'vulnerable' && comment === 'LAB_XSS_MARKER'
        ? `<svg data-rg-lab="xss" onload="document.documentElement.dataset.rgLab='xss'"></svg>`
        : escapeHtml(comment);
      return htmlResponse(200, `<!doctype html><p>Comment: ${reflected}</p>`);
    }

    case '/lab/api/file': {
      if (method !== 'GET') return methodNotAllowed();
      const requestedPath = url.searchParams.get('path') ?? '';
      if (!requestedPath) return jsonResponse(400, { error: 'A path is required' });

      const traversal = containsTraversal(requestedPath);
      if (profile === 'secure' && traversal) {
        return jsonResponse(400, { error: 'Path traversal is not allowed' });
      }

      const virtualPath = resolveVirtualPath(requestedPath);
      const content = VIRTUAL_FILES[virtualPath];
      if (content === undefined) return jsonResponse(404, { error: 'Synthetic file not found' });
      return jsonResponse(200, { path: virtualPath, content, synthetic: true });
    }

    case '/lab/api/discount': {
      if (method !== 'POST') return methodNotAllowed();
      const identity = getIdentity(headers);
      if (!identity) return jsonResponse(401, { error: 'Authentication required' });

      const body = parseBody(request.body);
      if (!body || body.code !== 'ONE-USE') {
        return jsonResponse(400, { error: 'Coupon code is invalid' });
      }

      const redemptionKey = `${identity.userId}:ONE-USE`;
      if (profile === 'secure' && state.redeemedCoupons.has(redemptionKey)) {
        return jsonResponse(409, { error: 'Coupon has already been used' });
      }
      if (profile === 'secure') state.redeemedCoupons.add(redemptionKey);
      return jsonResponse(200, { code: 'ONE-USE', discountPercent: 10, applied: true });
    }

    case '/lab/api/dependencies': {
      if (method !== 'GET') return methodNotAllowed();
      return jsonResponse(200, DEPENDENCIES);
    }

    default:
      return jsonResponse(404, { error: 'Route not found' });
  }
}

function normalizeHeaders(
  input: Record<string, string | string[] | undefined>,
): Map<string, string> {
  const normalized = new Map<string, string>();
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) normalized.set(key.toLowerCase(), Array.isArray(value) ? value.join(',') : value);
  }
  return normalized;
}

function getIdentity(headers: Map<string, string>): LabIdentity | undefined {
  const authorization = headers.get('authorization') ?? '';
  const bearer = /^Bearer\s+([a-z0-9_-]+)$/i.exec(authorization)?.[1]?.toLowerCase();
  if (bearer === 'alice') return { userId: '1', role: 'user' };
  if (bearer === 'bob') return { userId: '2', role: 'user' };
  if (bearer === 'admin') return { userId: '1', role: 'admin' };
  return undefined;
}

function parseBody(input: unknown): Record<string, unknown> | undefined {
  let value = input;
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value) as unknown;
    } catch {
      return undefined;
    }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function containsTraversal(path: string): boolean {
  return path.includes('\\') || path.startsWith('/') || path.split('/').some(segment => segment === '..');
}

function resolveVirtualPath(path: string): string {
  const segments = ['public'];
  for (const segment of path.replaceAll('\\', '/').split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments.join('/');
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function jsonResponse(status: number, value: unknown): LabResponse {
  return {
    status,
    headers: { 'content-type': JSON_CONTENT_TYPE, 'cache-control': 'no-store' },
    body: JSON.stringify(value),
  };
}

function htmlResponse(status: number, value: string): LabResponse {
  return {
    status,
    headers: { 'content-type': HTML_CONTENT_TYPE, 'cache-control': 'no-store' },
    body: value,
  };
}

function methodNotAllowed(): LabResponse {
  return jsonResponse(405, { error: 'Method not allowed' });
}
