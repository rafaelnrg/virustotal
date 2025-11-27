export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VT_BASE_URL = "https://www.virustotal.com/api/v3";

function getApiKey(): string {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) {
    throw new Error(
      "A variA�vel de ambiente da API de consulta nA�o estA� configurada."
    );
  }
  return key;
}

function jsonError(message: string, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json" }
  });
}

async function vtFetch(path: string, options: RequestInit = {}, apiKey?: string) {
  const key = apiKey ?? getApiKey();

  const response = await fetch(`${VT_BASE_URL}${path}`, {
    ...options,
    headers: {
      "x-apikey": key,
      ...(options.headers ?? {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      (data as { error?: { message?: string } })?.error?.message ??
      `Erro ${response.status} ao chamar a API de consulta.`;
    throw new Error(message);
  }

  return data;
}

function normalizeUrlForId(rawUrl: string): string {
  const trimmed = rawUrl.trim();

  try {
    const parsed = new URL(trimmed);
    // Normaliza apenas o caso comum de barra final na raiz:
    // https://exemplo.com.br/  -> https://exemplo.com.br
    if (parsed.pathname === "/" && !parsed.search && !parsed.hash) {
      parsed.pathname = "";
    }
    return parsed.toString();
  } catch {
    // Se nA�o for uma URL vA�lida, usa o valor original mesmo.
    return trimmed;
  }
}

function encodeUrlId(rawUrl: string): string {
  const normalized = normalizeUrlForId(rawUrl);
  const base64 = Buffer.from(normalized).toString("base64");
  return base64.replace(/=+$/u, "").replace(/\+/gu, "-").replace(/\//gu, "_");
}

async function handleUrlLookup(url: string) {
  const apiKey = getApiKey();

  // 1) Tenta buscar diretamente o objeto de URL (mais rA�pido para URLs jA� conhecidas).
  const urlId = encodeUrlId(url);
  try {
    const urlObject = await vtFetch(`/urls/${urlId}`, {}, apiKey);
    return urlObject;
  } catch {
    // Se nA�o existir ainda no VT, seguimos para o fluxo de submissA�o/analysis.
  }

  // 2) Envia a URL para anA�lise
  const encodedForm = new URLSearchParams({ url });
  const submission = await vtFetch(
    "/urls",
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body: encodedForm.toString()
    },
    apiKey
  );

  const analysisId = (submission as { data?: { id?: string } }).data?.id;
  if (!analysisId) {
    throw new Error("Resposta inesperada da API de consulta ao enviar a URL.");
  }

  // 3) Faz algumas tentativas de polling; se nA�o completar, retorna o A�ltimo estado mesmo assim.
  let attempts = 0;
  const maxAttempts = 6;
  const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  let lastAnalysis: unknown = submission;

  while (attempts < maxAttempts) {
    // eslint-disable-next-line no-await-in-loop
    const analysis = await vtFetch(`/analyses/${analysisId}`, {}, apiKey);
    lastAnalysis = analysis;

    const status = (analysis as { data?: { attributes?: { status?: string } } })
      .data?.attributes?.status;

    if (status === "completed") {
      break;
    }

    attempts += 1;
    // eslint-disable-next-line no-await-in-loop
    await delay(1500);
  }

  return lastAnalysis;
}

async function handleHashLookup(hash: string) {
  return vtFetch(`/files/${encodeURIComponent(hash)}`);
}

function normalizeDomain(rawDomain: string): string {
  const trimmed = rawDomain.trim();

  if (!trimmed) {
    return trimmed;
  }

  // Remove protocolo se o usuário colar algo como "https://exemplo.com/"
  const withoutProtocol = trimmed.replace(/^https?:\/\//iu, "");

  // Remove barras finais extras: "exemplo.com///" -> "exemplo.com"
  return withoutProtocol.replace(/\/+$/u, "");
}

async function handleDomainLookup(domain: string) {
  const cleanDomain = normalizeDomain(domain);
  return vtFetch(`/domains/${encodeURIComponent(cleanDomain)}`);
}

async function handleIpLookup(ip: string) {
  return vtFetch(`/ip_addresses/${encodeURIComponent(ip)}`);
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get("type");
  const value = searchParams.get("value");

  if (!type || !value) {
    return jsonError('ParA�metros "type" e "value" sA�o obrigatA3rios.');
  }

  try {
    let data: unknown;

    if (type === "url") {
      data = await handleUrlLookup(value);
    } else if (type === "hash") {
      data = await handleHashLookup(value);
    } else if (type === "domain") {
      data = await handleDomainLookup(value);
    } else if (type === "ip") {
      data = await handleIpLookup(value);
    } else {
      return jsonError(
        'Tipo invA�lido. Use "url", "hash", "domain" ou "ip".',
        400
      );
    }

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Erro desconhecido ao consultar a API de consulta.";
    return jsonError(message, 500);
  }
}

export async function POST(request: Request) {
  try {
    const apiKey = getApiKey();
    const contentType = request.headers.get("content-type") ?? "";

    if (!contentType.toLowerCase().includes("multipart/form-data")) {
      return jsonError(
        'Envie o arquivo usando "multipart/form-data" com o campo "file".'
      );
    }

    const formData = await request.formData();
    const file = formData.get("file");

    if (!(file instanceof File)) {
      return jsonError('Campo "file" Ac obrigatA3rio e deve ser um arquivo.');
    }

    const vtForm = new FormData();
    vtForm.append("file", file);

    const response = await fetch(`${VT_BASE_URL}/files`, {
      method: "POST",
      headers: {
        "x-apikey": apiKey
      },
      body: vtForm
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message =
        (data as { error?: { message?: string } })?.error?.message ??
        `Erro ${response.status} ao enviar arquivo para a API de consulta.`;
      return jsonError(message, 500);
    }

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Erro desconhecido ao enviar arquivo para a API de consulta.";
    return jsonError(message, 500);
  }
}
