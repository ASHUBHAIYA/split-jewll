export const CF_WORKER_KEY_NAME = 'ADMIN_MASTER_PIN';
export const DEFAULT_CF_WORKER_URL: string =
  (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_CF_WORKER_URL) || '';
export const DEFAULT_D1_DATABASE_NAME = 'jwellery_db';
export const DEFAULT_D1_DATABASE_ID = '';

/** Admin PIN of the current browser session (memory only). The Worker requires it for /set and /create-key. */
let sessionAdminPin = '';
export function clearAdminSession(): void {
  sessionAdminPin = '';
}

export interface CloudflareWorkerConfig {
  workerUrl: string;
  authToken: string;
  d1DatabaseName: string;
  d1DatabaseId: string;
}

// In-memory configuration for Cloudflare Workers D1 SQL endpoint
let inMemoryWorkerConfig: CloudflareWorkerConfig = {
  workerUrl: DEFAULT_CF_WORKER_URL,
  authToken: '',
  d1DatabaseName: DEFAULT_D1_DATABASE_NAME,
  d1DatabaseId: DEFAULT_D1_DATABASE_ID,
};

export function getCloudflareWorkerConfig(): CloudflareWorkerConfig {
  return { ...inMemoryWorkerConfig };
}

export function saveCloudflareWorkerConfig(
  workerUrl: string,
  authToken: string,
  d1DatabaseName: string = DEFAULT_D1_DATABASE_NAME,
  d1DatabaseId: string = DEFAULT_D1_DATABASE_ID
): void {
  inMemoryWorkerConfig = {
    ...inMemoryWorkerConfig,
    workerUrl: (workerUrl || DEFAULT_CF_WORKER_URL).trim(),
    authToken: (authToken || '').trim(),
    d1DatabaseName: (d1DatabaseName || DEFAULT_D1_DATABASE_NAME).trim(),
    d1DatabaseId: (d1DatabaseId || DEFAULT_D1_DATABASE_ID).trim(),
  };
}

/**
 * Checks if the local Go daemon is currently active and polling the Cloudflare Relay Worker (backed by D1)
 */
export async function checkCloudflareRelayDaemonOnline(
  licenseKey: string = ''
): Promise<{ online: boolean; lastSeenSecondsAgo?: number }> {
  const { workerUrl } = getCloudflareWorkerConfig();
  const targetUrl = (workerUrl || DEFAULT_CF_WORKER_URL).replace(/\/+$/, '');

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`${targetUrl}/relay/daemon-status?licenseKey=${encodeURIComponent(licenseKey)}`, {
      method: 'GET',
      signal: controller.signal,
    }).catch(async () => {
      return await fetch(`${targetUrl}/relay/status`, {
        method: 'GET',
        signal: controller.signal,
      });
    });

    clearTimeout(timer);

    if (res && res.ok) {
      const data = await res.json().catch(() => ({}));
      return {
        online: data.online === true || data.status === 'active' || (data.lastSeenSecondsAgo !== null && data.lastSeenSecondsAgo < 30),
        lastSeenSecondsAgo: data.lastSeenSecondsAgo,
      };
    }
  } catch {}

  return { online: false };
}

/**
 * Verifies Admin PIN directly against Cloudflare Workers D1 Database via HTTP request.
 */
export async function verifyAdminPinWithCloudflareKV(
  enteredPin: string
): Promise<{ success: boolean; message?: string }> {
  const cleanPin = enteredPin.trim();
  if (!cleanPin) {
    return { success: false, message: 'PIN cannot be empty' };
  }

  const { workerUrl, authToken } = getCloudflareWorkerConfig();
  const targetUrl = workerUrl || DEFAULT_CF_WORKER_URL;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const res = await fetch(`${targetUrl.replace(/\/+$/, '')}/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'VERIFY_PIN',
        pin: cleanPin,
      }),
      signal: controller.signal,
    }).catch(async () => {
      return await fetch(
        `${targetUrl.replace(/\/+$/, '')}?action=verify&pin=${encodeURIComponent(cleanPin)}`,
        {
          method: 'GET',
          headers,
          signal: controller.signal,
        }
      );
    });

    clearTimeout(timer);

    if (res && res.ok) {
      const data = await res.json().catch(() => null);
      if (data && (data.valid === true || data.success === true || data.verified === true)) {
        sessionAdminPin = cleanPin;
        return {
          success: true,
          message: data.initialized
            ? 'Master PIN created & initialized in Cloudflare D1 SQL Database!'
            : 'Authenticated successfully with Cloudflare D1 Database (SQL)',
        };
      } else {
        return {
          success: false,
          message: data?.error || data?.message || 'Incorrect Admin PIN. Verification failed against Cloudflare D1.',
        };
      }
    } else {
      const errText = await res?.text().catch(() => '');
      return {
        success: false,
        message: errText || `Cloudflare D1 Worker returned HTTP ${res?.status || 'Network Error'}`,
      };
    }
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Connection timeout';
    return {
      success: false,
      message: `Failed to reach Cloudflare D1 Worker (${errMsg}). Check connection to ${targetUrl}.`,
    };
  }
}

/**
 * Saves or updates the Admin PIN directly into Cloudflare D1 Database.
 */
export async function saveAdminPinToCloudflareKV(
  newPin: string
): Promise<{ success: boolean; message: string }> {
  const cleanPin = newPin.trim();
  if (cleanPin.length < 4) {
    return { success: false, message: 'PIN must be at least 4 digits' };
  }

  const { workerUrl, authToken } = getCloudflareWorkerConfig();
  const targetUrl = workerUrl || DEFAULT_CF_WORKER_URL;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4500);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    if (sessionAdminPin) headers['X-Admin-PIN'] = sessionAdminPin;
    const res = await fetch(`${targetUrl.replace(/\/+$/, '')}/set`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        action: 'SET_PIN',
        pin: cleanPin,
      }),
      signal: controller.signal,
    }).catch(async () => {
      return await fetch(`${targetUrl.replace(/\/+$/, '')}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          value: cleanPin,
        }),
        signal: controller.signal,
      });
    });

    clearTimeout(timer);

    if (res && res.ok) {
      sessionAdminPin = cleanPin;
      return {
        success: true,
        message: 'Admin Master PIN stored in Cloudflare D1 SQL database successfully!',
      };
    } else {
      const errText = await res?.text().catch(() => '');
      return {
        success: false,
        message: errText || `Failed to save to Cloudflare D1 (HTTP ${res?.status || 500})`,
      };
    }
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Network timeout';
    return {
      success: false,
      message: `Could not connect to Cloudflare D1: ${errMsg}`,
    };
  }
}

/**
 * Creates a license key through the Worker (admin PIN required) and records it in D1.
 */
export async function createLicenseKeyInCloudflareKV(params: {
  storeName: string;
  contactInfo?: string;
  durationMonths?: number;
}): Promise<{ success: boolean; licenseKey?: string; message?: string }> {
  const { workerUrl, authToken } = getCloudflareWorkerConfig();
  const targetUrl = (workerUrl || DEFAULT_CF_WORKER_URL).replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(targetUrl)) {
    return { success: false, message: 'Relay URL not set. Set VITE_CF_WORKER_URL in .env.local and restart the dev server.' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }
    if (sessionAdminPin) headers['X-Admin-PIN'] = sessionAdminPin;

    const res = await fetch(`${targetUrl}/create-key`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        storeName: params.storeName.trim(),
        contactInfo: (params.contactInfo || '').trim(),
        durationMonths: params.durationMonths || 12,
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && (data.licenseKey || data.key)) {
        return {
          success: true,
          licenseKey: data.licenseKey || data.key,
          message: 'Saved in Cloudflare D1 Database (SQL table: licenses)',
        };
      }
    }
    // A key that was never saved in D1 can never validate, so do not invent one locally.
    return { success: false, message: await readRelayError(res, `Worker returned HTTP ${res.status}`) };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Network timeout';
    return { success: false, message: `Could not reach the Worker: ${errMsg}` };
  }
}

async function readRelayError(res: Response, fallback: string): Promise<string> {
  const text = await res.text().catch(() => '');
  try {
    const j = JSON.parse(text);
    if (j && typeof j.error === 'string') return j.error;
  } catch {
    /* not JSON */
  }
  return text || fallback;
}

interface RelayJobResult {
  completed: boolean;
  status?: string;
  error?: string;
  tallyResponse?: string;
}

/**
 * Waits for the bridge to finish a job. The Worker holds each request open (up to ~20 s) and answers the
 * moment the result arrives, so a normal job costs 1-2 requests instead of one request per second.
 * Returns null if nothing arrived within maxMs.
 */
async function awaitRelayJob(
  targetUrl: string,
  headers: Record<string, string>,
  jobId: string,
  maxMs: number
): Promise<RelayJobResult | null> {
  const deadline = Date.now() + maxMs;
  let failures = 0;
  while (Date.now() < deadline) {
    const waitS = Math.max(1, Math.min(20, Math.floor((deadline - Date.now()) / 1000)));
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), (waitS + 10) * 1000);
      const res = await fetch(`${targetUrl}/relay/status?jobId=${encodeURIComponent(jobId)}&wait=${waitS}`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        failures = 0;
        const data = (await res.json().catch(() => ({}))) as RelayJobResult;
        if (data.completed) return data;
        // Not finished. An older Worker ignores ?wait= and answers instantly: never spin.
        if (Date.now() - startedAt < 800) await new Promise((r) => setTimeout(r, 1200));
        continue;
      }
      if (res.status === 400 || res.status === 404) {
        return { completed: true, status: 'unknown', error: await readRelayError(res, 'Job not found') };
      }
      failures++;
    } catch {
      failures++;
    }
    if (failures >= 5) return null;
    await new Promise((r) => setTimeout(r, Math.min(1000 * failures, 4000)));
  }
  return null;
}

/**
 * Queries Tally via Cloudflare Relay and waits for the bridge response
 */
export async function queryTallyViaCloudflareRelay(
  xmlQuery: string,
  licenseKey: string = ''
): Promise<{ success: boolean; tallyResponse?: string; error?: string }> {
  const { workerUrl, authToken } = getCloudflareWorkerConfig();
  const targetUrl = (workerUrl || DEFAULT_CF_WORKER_URL).replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(targetUrl)) {
    return { success: false, error: 'Relay URL not set. Set VITE_CF_WORKER_URL in .env.local and restart the dev server.' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

    const pushRes = await fetch(`${targetUrl}/relay/push`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        licenseKey: (licenseKey || '').trim(),
        xml: xmlQuery,
        timestamp: new Date().toISOString(),
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);
    if (!pushRes.ok) return { success: false, error: await readRelayError(pushRes, 'Push failed') };

    const pushData = await pushRes.json().catch(() => ({}));
    const jobId = pushData.jobId;
    if (!jobId) return { success: false, error: 'No Job ID' };

    const result = await awaitRelayJob(targetUrl, headers, jobId, 30000);
    if (!result) return { success: false, error: 'Timeout waiting for Go daemon' };
    if (result.status === 'success' || result.tallyResponse) {
      return { success: true, tallyResponse: result.tallyResponse };
    }
    return { success: false, error: result.error || 'Tally offline' };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Timeout';
    return { success: false, error: errMsg };
  }
}

/**
 * Pushes Tally XML through the Cloudflare relay and waits for the bridge's execution result
 */
export async function pushVoucherViaCloudflareRelay(
  xmlPayload: string,
  licenseKey: string = ''
): Promise<{ success: boolean; status?: string; message: string; tallyResponse?: string }> {
  const { workerUrl, authToken } = getCloudflareWorkerConfig();
  const targetUrl = (workerUrl || DEFAULT_CF_WORKER_URL).replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(targetUrl)) {
    return { success: false, message: 'Relay URL not set. Set VITE_CF_WORKER_URL in .env.local and restart the dev server.' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const pushRes = await fetch(`${targetUrl}/relay/push`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        licenseKey: (licenseKey || '').trim(),
        xml: xmlPayload,
        timestamp: new Date().toISOString(),
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!pushRes.ok) {
      return { success: false, message: await readRelayError(pushRes, 'Relay push failed') };
    }

    const pushData = await pushRes.json().catch(() => ({}));
    const jobId = pushData.jobId;
    if (!jobId) {
      return { success: false, message: 'No Job ID returned from Cloudflare' };
    }

    // The Worker expires an unclaimed job after ~45 s, so wait a little longer than that.
    const sData = await awaitRelayJob(targetUrl, headers, jobId, 60000);
    if (!sData) {
      return {
        success: false,
        status: 'pending',
        message: 'No answer from the bridge yet. Check the Tally Day Book before pushing again.',
      };
    }

    if (sData.status === 'success') {
      return {
        success: true,
        status: 'success',
        message: 'Vouchers created in Tally via local bridge daemon!',
        tallyResponse: sData.tallyResponse,
      };
    }
    if (sData.status === 'tally_offline') {
      return {
        success: false,
        status: 'tally_offline',
        message: sData.error || 'Tally is offline on port 9000. Please open your company in Tally.',
      };
    }
    if (sData.status === 'tally_rejected') {
      return {
        success: false,
        status: 'tally_rejected',
        message: sData.error || 'Tally rejected the vouchers. Check ledgers and dates.',
        tallyResponse: sData.tallyResponse,
      };
    }
    return {
      success: false,
      status: sData.status || 'unknown',
      message: sData.error || 'The relay could not confirm this job. Check the Tally Day Book before retrying.',
    };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Timeout';
    return { success: false, message: `Cloudflare Relay unreachable: ${errMsg}` };
  }
}

/**
 * D1 now only stores the admin PIN and licenses (the relay queue and bridge heartbeat live in a Durable Object).
 * The full, deployable Worker lives in /cloudflare-worker (src/index.js, schema.sql, wrangler.toml).
 */
export const SAMPLE_D1_SQL_SCHEMA = `-- Run once:  npx wrangler d1 execute jwellery_db --remote --file=cloudflare-worker/schema.sql
CREATE TABLE IF NOT EXISTS admin_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS licenses (
  license_key TEXT PRIMARY KEY, store_name TEXT NOT NULL, contact_info TEXT DEFAULT '', duration_months INTEGER DEFAULT 12,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, machine_id TEXT DEFAULT '', status TEXT DEFAULT 'active',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
DROP TABLE IF EXISTS relay_queue;
DROP TABLE IF EXISTS daemon_heartbeats;
`;

/** The Worker source is no longer duplicated here: deploy /cloudflare-worker (see its README.md). */
export const SAMPLE_CF_WORKER_CODE = '// See cloudflare-worker/src/index.js';
