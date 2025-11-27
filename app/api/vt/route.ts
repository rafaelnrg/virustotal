import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VT_BASE_URL = "https://www.virustotal.com/api/v3";

function getApiKey(): string {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) {
    throw new Error(
      "A variável de ambiente VIRUSTOTAL_API_KEY não está configurada."
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

async function vtFetch(
  path: string,
  options: RequestInit = {},
  apiKey?: string
) {
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
      `Erro ${response.status} ao chamar o VirusTotal.`;
    throw new Error(message);
  }

  return data;
}

async function handleUrlLookup(url: string) {
  const apiKey = getApiKey();

  // 1) Envia a URL para análise
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
    throw new Error("Resposta inesperada do VirusTotal ao enviar a URL.");
  }

  // 2) Faz polling até o status ficar "completed" ou estourar o limite
  let attempts = 0;
  const maxAttempts = 10;
  const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  while (attempts < maxAttempts) {
    // eslint-disable-next-line no-await-in-loop
    const analysis = await vtFetch(`/analyses/${analysisId}`, {}, apiKey);
    const status = (analysis as { data?: { attributes?: { status?: string } } })
      .data?.attributes?.status;

    if (status === "completed") {
      return analysis;
    }

    attempts += 1;
    // eslint-disable-next-line no-await-in-loop
    await delay(1500);
  }

  throw new Error(
    "Tempo limite ao aguardar a conclusão da análise da URL no VirusTotal."
  );
}

async function handleHashLookup(hash: string) {
  return vtFetch(`/files/${encodeURIComponent(hash)}`);
}

async function handleDomainLookup(domain: string) {
  return vtFetch(`/domains/${encodeURIComponent(domain)}`);
}

async function handleIpLookup(ip: string) {
  return vtFetch(`/ip_addresses/${encodeURIComponent(ip)}`);
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get("type");
  const value = searchParams.get("value");

  if (!type || !value) {
    return jsonError('Parâmetros "type" e "value" são obrigatórios.');
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
        'Tipo inválido. Use "url", "hash", "domain" ou "ip".',
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
        : "Erro desconhecido ao consultar o VirusTotal.";
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
      return jsonError('Campo "file" é obrigatório e deve ser um arquivo.');
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
        `Erro ${response.status} ao enviar arquivo para o VirusTotal.`;
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
        : "Erro desconhecido ao enviar arquivo para o VirusTotal.";
    return jsonError(message, 500);
  }
}

