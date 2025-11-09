// /api/free/bypass.js
import dns from 'dns/promises';
import { URL } from 'url';

// Config (use Vercel env vars to override)
const UPSTREAM_BASE = process.env.UPSTREAM_BASE || 'https://trw.lat';
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 10000);
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 60);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 30);

// Simple per-instance in-memory cache and rate limiter (ephemeral on Vercel)
const cache = new Map(); // key -> { value, expiresAt }
const rateMap = new Map(); // ip -> { count, windowStart }

function cleanCache() {
  const now = Date.now();
  for (const [k, v] of cache.entries()) {
    if (v.expiresAt <= now) cache.delete(k);
  }
}

// Basic helper to block common private/reserved IP ranges and local hostnames
function isPrivateOrLoopbackAddress(ip) {
  if (!ip) return true;
  // IPv6 loopback
  if (ip === '::1') return true;
  // IPv4 quick checks
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('169.254.') || ip.startsWith('192.168.')) return true;
  // 172.16.0.0 – 172.31.255.255
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

// minimal hostname safety checks (block obvious local names)
function isUnsafeHostname(hostname) {
  if (!hostname) return true;
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.local') || lower.endsWith('.internal')) return true;
  return false;
}

// Try common locations for a final URL inside upstream JSON
function tryExtractFinalUrl(body) {
  if (!body) return null;
  const candidateIsUrl = (s) => {
    if (typeof s !== 'string') return false;
    try {
      const u = new URL(s);
      return ['http:', 'https:'].includes(u.protocol);
    } catch { return false; }
  };

  const directFields = ['destination', 'final', 'final_url', 'resolved', 'url', 'redirect', 'redirect_url', 'final_destination'];
  for (const f of directFields) {
    if (f in body && candidateIsUrl(body[f])) return body[f];
  }
  if (body.data && typeof body.data === 'object') {
    for (const f of directFields) {
      if (f in body.data && candidateIsUrl(body.data[f])) return body.data[f];
    }
    if (Array.isArray(body.data)) {
      for (const item of body.data) {
        if (item && typeof item === 'object') {
          for (const f of directFields) {
            if (f in item && candidateIsUrl(item[f])) return item[f];
          }
        }
      }
    }
  }
  // shallow scan values
  for (const v of Object.values(body)) {
    if (candidateIsUrl(v)) return v;
  }
  return null;
}

// Serverless handler
export default async function handler(req, res) {
  cleanCache();

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  const target = req.query?.url;
  if (!target) return res.status(400).json({ success: false, error: "Missing 'url' query parameter." });

  // Parse and basic validation
  let parsed;
  try {
    parsed = new URL(String(target));
  } catch {
    return res.status(400).json({ success: false, error: 'Invalid URL.' });
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ success: false, error: 'Only http/https URLs allowed.' });
  }
  if (isUnsafeHostname(parsed.hostname)) {
    return res.status(400).json({ success: false, error: 'Refusing unsafe hostname (localhost/local/internal).' });
  }

  // Simple per-IP rate limit (per-instance)
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const slot = rateMap.get(ip) || { count: 0, windowStart: now };
  if (now - slot.windowStart > RATE_LIMIT_WINDOW_MS) {
    slot.count = 0;
    slot.windowStart = now;
  }
  slot.count += 1;
  rateMap.set(ip, slot);
  if (slot.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ success: false, error: 'Too many requests (rate limit).' });
  }

  // SSRF protection: resolve hostname and ensure not private IP
  try {
    const records = await dns.lookup(parsed.hostname, { all: true });
    if (!records || records.length === 0) throw new Error('No DNS records');
    for (const r of records) {
      if (isPrivateOrLoopbackAddress(r.address)) {
        return res.status(400).json({ success: false, error: 'Refusing to resolve to private/loopback address.' });
      }
    }
  } catch (err) {
    return res.status(400).json({ success: false, error: 'DNS lookup failed or host unsafe.' });
  }

  // Cache check (cache keyed by the raw target)
  const cacheKey = `final:${target}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.status(200).json({ success: true, cached: true, final: cached });
  }

  // Build upstream call
  const upstreamUrl = `${UPSTREAM_BASE}/api/free/bypass?url=${encodeURIComponent(target)}`;

  // Call upstream with timeout
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(upstreamUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    // try parse JSON (if not JSON, fallback)
    const contentType = resp.headers.get('content-type') || '';
    let body = null;
    if (contentType.includes('application/json')) {
      body = await resp.json();
    } else {
      // upstream unexpectedly returned non-JSON — attempt text parse
      const text = await resp.text();
      try {
        body = JSON.parse(text);
      } catch {
        body = { raw: text };
      }
    }

    // Attempt to extract final URL
    const final = tryExtractFinalUrl(body);
    if (final) {
      // set cache (ephemeral)
      cache.set(cacheKey, final, { expiresAt: Date.now() + CACHE_TTL_SECONDS * 1000 });
      // Note: Map doesn't support expires natively, we store a tuple (value, expiresAt)
      // we'll store as object to follow cleanCache check
      cache.set(cacheKey, final);
      return res.status(200).json({ success: true, final });
    }

    // Fallback: return upstream body so caller can inspect
    return res.status(200).json({
      success: false,
      message: 'Could not extract final URL from upstream response; upstream body returned under "upstream".',
      upstream_status: resp.status,
      upstream: body
    });

  } catch (err) {
    clearTimeout(timeout);
    const errMsg = err?.name === 'AbortError' ? 'Upstream timeout' : (err?.message || 'Upstream request failed');
    return res.status(502).json({ success: false, error: errMsg });
  }
}
