// agentbox: Pi provider for `agentbox pi --model ollama/<m> | remote/<name>`
// (PLAN §2.5). Loaded by /usr/local/bin/pi (pi-wrapper) with --extension.
// Root-owned in the image: the CLI never writes ~/.pi/agent/models.json.
// Endpoints are fixed here; only the route kind and model id come from env
// (AGENTBOX_MODEL_ROUTE, AGENTBOX_MODEL_ID, set by the CLI on the exec).
// The router key is read by name ($AGENTBOX_ROUTER_MASTER_KEY, Pi env
// interpolation), never passed in argv. No env: registers nothing.
const ROUTES: Record<string, { provider: string; name: string; baseUrl: string; apiKey: string }> = {
  ollama: {
    provider: "agentbox-ollama",
    name: "agentbox ollama (host)",
    baseUrl: "http://ollama-gate:11434/v1",
    apiKey: "ollama",
  },
  remote: {
    provider: "agentbox-router",
    name: "agentbox router",
    baseUrl: "http://router:4000/v1",
    apiKey: "$AGENTBOX_ROUTER_MASTER_KEY",
  },
};
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:\/@+-]{0,199}$/;

export default function (pi: any) {
  const kind = process.env.AGENTBOX_MODEL_ROUTE;
  const id = process.env.AGENTBOX_MODEL_ID;
  if (!kind || !id) return;
  const r = ROUTES[kind];
  if (!r || !MODEL_ID.test(id)) return;
  pi.registerProvider(r.provider, {
    name: r.name,
    baseUrl: r.baseUrl,
    api: "openai-completions",
    apiKey: r.apiKey,
    models: [
      {
        id,
        name: id,
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 32768,
        maxTokens: 8192,
      },
    ],
  });
}
