import assert from 'node:assert/strict';
import test from 'node:test';

import { createLabState, handleLabRequest, resetLabState } from './lab-target.ts';
import type { LabProfile } from './lab-target.ts';

type LabResponse = ReturnType<typeof handleLabRequest>;

function request(
  method: string,
  url: string,
  options: { headers?: Record<string, string>; body?: unknown } = {},
): Parameters<typeof handleLabRequest>[0] {
  return { method, url, headers: options.headers ?? {}, body: options.body };
}

function json(response: LabResponse): any {
  return JSON.parse(response.body);
}

function bearer(user: 'alice' | 'bob' | 'admin'): Record<string, string> {
  return { authorization: `Bearer ${user}` };
}

test('records demonstrate horizontal IDOR only in the vulnerable profile', () => {
  const vulnerable = handleLabRequest(
    request('GET', '/lab/api/records?user_id=2', { headers: bearer('alice') }),
    'vulnerable',
    createLabState(),
  );
  const secure = handleLabRequest(
    request('GET', '/lab/api/records?user_id=2', { headers: bearer('alice') }),
    'secure',
    createLabState(),
  );

  assert.equal(vulnerable.status, 200);
  assert.equal(json(vulnerable).record.ownerUserId, '2');
  assert.equal(secure.status, 403);
});

test('admin endpoint is open in the vulnerable profile and role-checked in the secure profile', () => {
  const state = createLabState();
  assert.equal(
    handleLabRequest(request('GET', '/lab/api/admin'), 'vulnerable', state).status,
    200,
  );
  assert.equal(
    handleLabRequest(request('GET', '/lab/api/admin'), 'secure', state).status,
    401,
  );
  assert.equal(
    handleLabRequest(
      request('GET', '/lab/api/admin', { headers: bearer('alice') }),
      'secure',
      state,
    ).status,
    403,
  );
  assert.equal(
    handleLabRequest(
      request('GET', '/lab/api/admin', { headers: bearer('admin') }),
      'secure',
      state,
    ).status,
    200,
  );
  assert.equal(
    handleLabRequest(
      request('GET', '/lab/api/admin', {
        headers: { 'x-user-id': '1', 'x-lab-role': 'admin' },
      }),
      'secure',
      state,
    ).status,
    401,
  );
});

test('search canary broadens only vulnerable matching; secure search treats it literally', () => {
  const url = '/lab/api/search?q=LAB_SEARCH_ALL';
  const vulnerable = handleLabRequest(request('GET', url), 'vulnerable', createLabState());
  const secure = handleLabRequest(request('GET', url), 'secure', createLabState());

  assert.equal(json(vulnerable).results.length, 3);
  assert.deepEqual(json(secure).results, []);
});

test('comment route reflects markup in HTML only when vulnerable and escapes it in the secure profile', () => {
  const marker = 'LAB_XSS_MARKER';
  const url = `/lab/api/comment?q=${encodeURIComponent(marker)}`;
  const vulnerable = handleLabRequest(request('GET', url), 'vulnerable', createLabState());
  const secure = handleLabRequest(request('GET', url), 'secure', createLabState());

  assert.match(vulnerable.headers['content-type'], /^text\/html/);
  assert.equal(vulnerable.body, `<!doctype html><p>Comment: <svg data-rg-lab="xss" onload="document.documentElement.dataset.rgLab='xss'"></svg></p>`);
  assert.match(secure.headers['content-type'], /^text\/html/);
  assert.equal(secure.body, `<!doctype html><p>Comment: ${marker}</p>`);
  assert.match(vulnerable.body, /data-rg-lab="xss" onload=/);
  assert.doesNotMatch(secure.body, /<svg|onload=/);
});

test('file route exposes only the fake in-memory file through vulnerable traversal', () => {
  const url = `/lab/api/file?path=${encodeURIComponent('../private/lab-secret.txt')}`;
  const vulnerable = handleLabRequest(request('GET', url), 'vulnerable', createLabState());
  const secure = handleLabRequest(request('GET', url), 'secure', createLabState());

  assert.equal(vulnerable.status, 200);
  assert.match(json(vulnerable).content, /synthetic lab secret/i);
  assert.equal(json(vulnerable).path, 'private/lab-secret.txt');
  assert.equal(secure.status, 400);
});

test('ONE-USE discount repeats when vulnerable and is single-use when secure', () => {
  const state = createLabState();
  const couponRequest = request('POST', '/lab/api/discount', {
    headers: bearer('alice'),
    body: { code: 'ONE-USE' },
  });

  assert.equal(handleLabRequest(couponRequest, 'vulnerable', state).status, 200);
  assert.equal(handleLabRequest(couponRequest, 'vulnerable', state).status, 200);
  assert.equal(handleLabRequest(couponRequest, 'secure', state).status, 200);
  assert.equal(handleLabRequest(couponRequest, 'secure', state).status, 409);

  resetLabState(state);
  assert.equal(handleLabRequest(couponRequest, 'secure', state).status, 200);
});

test('dependency inventory contains a clearly synthetic warning in both profiles', () => {
  const vulnerable = handleLabRequest(
    request('GET', '/lab/api/dependencies'),
    'vulnerable',
    createLabState(),
  );
  const secure = handleLabRequest(
    request('GET', '/lab/api/dependencies'),
    'secure',
    createLabState(),
  );

  assert.equal(vulnerable.status, 200);
  assert.deepEqual(json(vulnerable), json(secure));
  assert.equal(json(secure).synthetic, true);
  assert.equal(json(secure).dependencies[0].advisory, 'RG-DEMO-001');
  assert.equal(json(secure).dependencies[0].requiresLiveValidation, true);
});

test('unrecognized routes return a deterministic not-found response', () => {
  const response = handleLabRequest(
    request('GET', '/lab/api/missing'),
    'secure' satisfies LabProfile,
    createLabState(),
  );

  assert.equal(response.status, 404);
});
