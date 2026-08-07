# Chickpea auth deploy-button proof

Disposable U8P fixture for validating Cloudflare's public Deploy button with one secret prompt, automatic D1 and Durable Object provisioning, ordered Better Auth migrations, and `/admin/setup` reachability.

Generate the only required secret with:

```sh
openssl rand -hex 32
```

After deployment, open `/__deploy-proof` to verify the migration ledger and bindings, then continue to `/admin/setup`.
