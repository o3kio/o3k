// get.o3k.io installer endpoint — minimal Cloudflare Worker (ES module).
//
// NOT REQUIRED FOR INSTALLATION. The production installation path is a
// Cloudflare Redirect Rule (see cloudflare-redirect.md): get.o3k.io 302s
// directly to the tagged GitHub Release install.sh asset. This worker is
// retained ONLY for optional future channel/version functionality and is
// not a trust dependency of the installer.
//
// No framework, no KV, no release-asset proxying. The channel table is tiny
// and versioned with the code: it is embedded as src/assets.js, regenerated
// from the repo's single sources of truth by sync.sh
// (packaging/get-o3k.sh + packaging/channels.yaml). Large release archives
// are served by GitHub Releases, never through this worker.
//
// Route map:
//   GET /                     -> packaging/get-o3k.sh verbatim
//   GET /install.sh           -> packaging/get-o3k.sh verbatim
//   GET /version              -> current advertised version (alpha target)
//   GET /channel/<name>       -> channel version as plain text (404 if unknown)
//   GET /v<version>           -> same script with an O3K_PINNED_VERSION first
//                                line; 400 unless the version matches the
//                                ADR-0130 fence (never a redirect, never main)
//   everything else           -> 404 with a tiny helpful body
//
// The O3K_PINNED_VERSION line is a plain shell assignment when the stream is
// piped to sh; packaging/get-o3k.sh resolves it with precedence
// O3K_VERSION env > O3K_PINNED_VERSION > the baked O3K_INSTALLER_VERSION
// release pin. The installer never consults a channel service.

import { SCRIPT, CHANNELS, ALPHA_TARGET } from './assets.js';

// ADR-0130 release-version fence, identical to check_version_format() in
// packaging/get-o3k.sh: numeric release version with one or two dots and an
// optional dot-separated alphanumeric prerelease suffix; one optional leading
// "v" is stripped before matching.
const VERSION_RE = /^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/;

const TEXT_PLAIN = 'text/plain; charset=utf-8';

const NOT_FOUND_BODY =
  'not found. Routes: GET /, GET /install.sh, GET /version, ' +
  'GET /channel/<name>, GET /v<version>. ' +
  'Release archives are served by GitHub Releases, never through this endpoint.\n';

function text(body, { status = 200, cache = true } = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': TEXT_PLAIN,
      'Cache-Control': cache ? 'public, max-age=60' : 'no-store',
    },
  });
}

export default {
  async fetch(request) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return text('method not allowed; this endpoint only serves GET requests\n', {
        status: 405,
        cache: false,
      });
    }

    const { pathname } = new URL(request.url);

    // Root and /install.sh serve the wrapper script verbatim (no redirect).
    if (pathname === '/' || pathname === '/install.sh') {
      return text(SCRIPT);
    }

    // Current advertised version: the alpha channel target. A future stable
    // channel may change this definition (e.g. advertise stable when it
    // exists); until then alpha IS the advertised release line.
    if (pathname === '/version') {
      return text(ALPHA_TARGET);
    }

    // Plain-text channel lookup; never a redirect, never main/latest.
    if (pathname.startsWith('/channel/')) {
      const name = pathname.slice('/channel/'.length);
      const version = CHANNELS[name];
      if (version === undefined) {
        return text(
          `unknown channel: ${name}. Known channels: ${Object.keys(CHANNELS).join(', ')}\n`,
          { status: 404, cache: false },
        );
      }
      return text(version);
    }

    // Pinned-version path: same wrapper with the pin line as the first line.
    if (pathname.startsWith('/v')) {
      const version = pathname.slice('/v'.length);
      const bare = version.startsWith('v') ? version.slice(1) : version;
      if (!VERSION_RE.test(bare)) {
        return text(
          `invalid version path: /v${version} — expected a published release version like /v0.4.0-rc.2\n`,
          { status: 400, cache: false },
        );
      }
      return text(`O3K_PINNED_VERSION="${version}"\n${SCRIPT}`);
    }

    return text(NOT_FOUND_BODY, { status: 404, cache: false });
  },
};
