// test.mjs — plain node:test suite for the get.o3k.io worker handler.
// Run from anywhere: node --test packaging/get-o3k-worker/test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import handler from './src/index.js';
import { SCRIPT, CHANNELS, ALPHA_TARGET } from './src/assets.js';

const repoScriptPath = fileURLToPath(
  new URL('../../packaging/get-o3k.sh', import.meta.url),
);
const REPO_SCRIPT = readFileSync(repoScriptPath, 'utf8');

function request(method, path) {
  return new Request(`https://get.o3k.io${path}`, { method });
}

async function body(response) {
  return response.text();
}

test('embedded script snapshot matches packaging/get-o3k.sh byte-for-byte', () => {
  // Independent of sync.sh: a direct comparison of the committed snapshot
  // against the single source of truth in the repo.
  assert.equal(SCRIPT, REPO_SCRIPT);
});

test('GET / serves packaging/get-o3k.sh verbatim', async () => {
  const response = await handler.fetch(request('GET', '/'));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(await body(response), REPO_SCRIPT);
});

test('GET /install.sh matches packaging/get-o3k.sh byte-for-byte', async () => {
  const response = await handler.fetch(request('GET', '/install.sh'));
  assert.equal(response.status, 200);
  assert.equal(await body(response), REPO_SCRIPT);
});

test('GET /version returns the alpha channel target', async () => {
  const response = await handler.fetch(request('GET', '/version'));
  assert.equal(response.status, 200);
  assert.equal(await body(response), ALPHA_TARGET);
  // The version constants are intentional: a channel bump to a new release
  // must update this test (and packaging/channels.yaml) deliberately.
  assert.equal(ALPHA_TARGET, 'v0.4.0-rc.4');
});

test('GET /channel/alpha returns v0.4.0-rc.4 as plain text', async () => {
  const response = await handler.fetch(request('GET', '/channel/alpha'));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(await body(response), 'v0.4.0-rc.4');
  // Intentional pin: see the version-constant comment on GET /version.
  assert.equal(CHANNELS.alpha, 'v0.4.0-rc.4');
});

test('GET /channel/<unknown> is a 404, never a redirect and never main', async () => {
  const response = await handler.fetch(request('GET', '/channel/bogus'));
  assert.equal(response.status, 404);
  const text = await body(response);
  assert.match(text, /unknown channel: bogus/);
  assert.doesNotMatch(text, /main/);
});

test('GET /v0.4.0-rc.4 prepends the exact pin line and then equals the script', async () => {
  const response = await handler.fetch(request('GET', '/v0.4.0-rc.4'));
  assert.equal(response.status, 200);
  const text = await body(response);
  const expected = 'O3K_PINNED_VERSION="0.4.0-rc.4"\n' + REPO_SCRIPT;
  assert.equal(text, expected);
  assert.ok(text.startsWith('O3K_PINNED_VERSION="0.4.0-rc.4"\n'));
  assert.equal(text.slice('O3K_PINNED_VERSION="0.4.0-rc.4"\n'.length), REPO_SCRIPT);
});

test('GET /v0.4.0-rc.4 pin line is a plain sh assignment the wrapper parses', async () => {
  // packaging/get-o3k.sh resolves O3K_VERSION env > O3K_PINNED_VERSION >
  // the baked O3K_INSTALLER_VERSION pin, and VERSION_NO_V strips a leading
  // "v" — mirror that resolution on the served bytes to prove the line is
  // exactly what the wrapper expects.
  const response = await handler.fetch(request('GET', '/v0.4.0-rc.4'));
  const text = await body(response);
  const firstLine = text.split('\n', 1)[0];
  assert.match(firstLine, /^O3K_PINNED_VERSION="[^"]*"$/);
  const pinned = firstLine.slice('O3K_PINNED_VERSION="'.length, -1);
  const version = pinned.startsWith('v') ? pinned.slice(1) : pinned;
  assert.match(version, /^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/);
});

test('GET /v/bogus is a 400', async () => {
  const response = await handler.fetch(request('GET', '/v/bogus'));
  assert.equal(response.status, 400);
  assert.match(await body(response), /invalid version path/);
});

test('GET /v0.4.0-rc.4/evil (traversal-shaped) is a 400, not a file read', async () => {
  const response = await handler.fetch(request('GET', '/v0.4.0-rc.4/evil'));
  assert.equal(response.status, 400);
});

test('unknown paths are 404 with a tiny helpful body', async () => {
  const response = await handler.fetch(request('GET', '/release/v0.4.0-rc.4'));
  assert.equal(response.status, 404);
  assert.match(await body(response), /not found/);
});

test('non-GET methods are rejected without serving the script', async () => {
  for (const method of ['POST', 'PUT', 'DELETE']) {
    const response = await handler.fetch(request(method, '/install.sh'));
    assert.equal(response.status, 405);
    assert.doesNotMatch(await body(response), /#!/);
  }
});
