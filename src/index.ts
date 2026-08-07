import { DurableObject } from "cloudflare:workers";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";

interface Env {
  AUTH_DB: D1Database;
  AUTH_GUARD: DurableObjectNamespace<AuthGuard>;
  CHICKPEA_RECOVERY_TOKEN: string;
}

const encoder = new TextEncoder();

function decodeRecoveryToken(value: string): Uint8Array {
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return Uint8Array.from(value.match(/.{2}/g)!, (byte) => Number.parseInt(byte, 16));
  }

  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (decoded.byteLength !== 32) throw new Error("invalid recovery token");
  return decoded;
}

async function deriveBetterAuthSecret(recoveryToken: string): Promise<string> {
  const input = decodeRecoveryToken(recoveryToken);
  const key = await crypto.subtle.importKey("raw", input, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: encoder.encode("chickpea/better-auth/v1"),
    },
    key,
    256,
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createAuth(env: Env, origin: string) {
  return betterAuth({
    baseURL: origin,
    secret: await deriveBetterAuthSecret(env.CHICKPEA_RECOVERY_TOKEN),
    database: env.AUTH_DB,
    emailAndPassword: { enabled: true, disableSignUp: true },
    session: {
      expiresIn: 60 * 60 * 4,
      updateAge: 60 * 60,
      cookieCache: { enabled: false },
      additionalFields: {
        absoluteExpiresAt: { type: "date", required: true, input: false },
      },
    },
    plugins: [organization()],
  });
}

export class AuthGuard extends DurableObject<Env> {
  async ping(): Promise<{ storage: "sqlite"; ok: true }> {
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS deploy_proof (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL)",
    );
    return { storage: "sqlite", ok: true };
  }
}

async function deploymentProof(request: Request, env: Env): Promise<Response> {
  const tableRows = await env.AUTH_DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
  ).all<{ name: string }>();
  const migrationRows = await env.AUTH_DB.prepare(
    "SELECT name FROM d1_migrations ORDER BY id",
  ).all<{ name: string }>();
  const auth = await createAuth(env, new URL(request.url).origin);
  const guard = env.AUTH_GUARD.get(env.AUTH_GUARD.idFromName("deploy-proof"));
  const ping = await guard.ping();

  return Response.json({
    ok: true,
    betterAuth: typeof auth.handler === "function",
    recoveryTokenAccepted: true,
    derivedSecretExposed: false,
    tables: tableRows.results.map((row) => row.name),
    migrations: migrationRows.results.map((row) => row.name),
    durableObject: ping,
    next: "/admin/setup",
  });
}

function setupPage(): Response {
  return new Response(
    `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Set up Chickpea</title><body><main><h1>Set up Chickpea</h1><p>Your private Chickpea instance is ready. Create the first owner to continue.</p><form><label>Recovery secret <input name="recovery" autocomplete="off"></label><label>Name <input name="name" autocomplete="name"></label><label>Email <input type="email" name="email" autocomplete="email"></label><label>Password <input type="password" name="password" autocomplete="new-password"></label><button type="button">Create owner</button></form></main></body></html>`,
    { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } },
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/admin/setup" && request.method === "GET") return setupPage();
    if (url.pathname === "/__deploy-proof" && request.method === "GET") {
      try {
        return await deploymentProof(request, env);
      } catch {
        return Response.json({ ok: false, error: "deployment_not_ready" }, { status: 503 });
      }
    }
    if (url.pathname.startsWith("/api/auth/")) return new Response("Not Found", { status: 404 });
    return Response.redirect(new URL("/admin/setup", url), 302);
  },
};
