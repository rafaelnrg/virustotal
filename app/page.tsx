"use client";

import React, { FormEvent, useState } from "react";

type Mode = "url" | "hash" | "domain" | "ip" | "file";

type ApiError = {
  error: string;
};

type VTResultCardProps = {
  mode: Mode;
  result: any;
  queryLabel: string;
};

function VTResultCard({ mode, result, queryLabel }: VTResultCardProps) {
  const [activeTab, setActiveTab] =
    useState<"detection" | "details" | "community">("detection");

  const data = (result && result.data) || {};
  const attributes = (data && data.attributes) || {};

  const stats =
    attributes.last_analysis_stats ||
    attributes.stats ||
    attributes.analysis_stats ||
    {};

  const resultsMap =
    attributes.last_analysis_results ||
    attributes.results ||
    attributes.analysis_results ||
    {};

  const engines = Object.values(resultsMap as Record<string, any>) as Array<{
    engine_name?: string;
    category?: string;
    result?: string | null;
    method?: string;
  }>;

  const maliciousCount =
    (stats.malicious || 0) + (stats.suspicious || 0) + (stats.malware || 0);
  const harmlessCount = stats.harmless || 0;
  const undetectedCount = stats.undetected || 0;
  const timeoutCount = stats.timeout || 0;

  const totalEngines =
    engines.length ||
    maliciousCount + harmlessCount + undetectedCount + timeoutCount ||
    0;

  const analysisDate =
    attributes.last_analysis_date ||
    attributes.date ||
    attributes.last_modification_date;

  const isMalicious = maliciousCount > 0;

  const message =
    totalEngines === 0
      ? "Nenhum dado de detecção disponível."
      : !isMalicious
      ? "Nenhum mecanismo de segurança marcou este recurso como malicioso."
      : `${maliciousCount} mecanismo(s) marcaram este recurso como malicioso ou suspeito.`;

  const typeLabel =
    mode === "url"
      ? "URL"
      : mode === "hash"
      ? "Hash de arquivo"
      : mode === "domain"
      ? "Domínio"
      : mode === "ip"
      ? "Endereço IP"
      : "Arquivo enviado";

  const bannerClass = `vt-banner ${
    isMalicious ? "vt-banner-bad" : "vt-banner-good"
  }`;
  const scoreCircleClass = `vt-score-circle ${
    isMalicious ? "vt-score-circle-bad" : "vt-score-circle-good"
  }`;
  const mainMessageClass = `vt-main-message ${
    isMalicious ? "vt-main-message-bad" : "vt-main-message-good"
  }`;
  const cardClass = `card card-result ${
    totalEngines === 0
      ? "card-result-unknown"
      : isMalicious
      ? "card-result-bad"
      : "card-result-good"
  }`;

  const categories = attributes.categories || {};
  const totalVotes = attributes.total_votes || {};
  const reputation = attributes.reputation as number | undefined;

  return (
    <section className={cardClass}>
      <header className="card-header">
        <h2>Resultado da análise</h2>
      </header>

      <div className={bannerClass}>
        <div className="vt-score">
          <div className={scoreCircleClass}>
            <span className="vt-score-number">{maliciousCount}</span>
            <span className="vt-score-total">/ {totalEngines || "?"}</span>
          </div>
          <span className="vt-score-label">Detecções</span>
        </div>

        <div className="vt-main">
          <p className={mainMessageClass}>{message}</p>
          <p className="vt-main-target">
            <span className="vt-main-target-label">{typeLabel} analisado:</span>
            <span className="vt-main-target-value">{queryLabel}</span>
          </p>

          <div className="vt-meta">
            {typeof attributes.status === "string" && (
              <div className="vt-meta-item">
                <span className="vt-meta-label">Status</span>
                <span className="vt-meta-value">{attributes.status}</span>
              </div>
            )}
            {typeof attributes.http_status === "number" && (
              <div className="vt-meta-item">
                <span className="vt-meta-label">HTTP Status</span>
                <span className="vt-meta-value">{attributes.http_status}</span>
              </div>
            )}
            {typeof attributes.content_type === "string" && (
              <div className="vt-meta-item">
                <span className="vt-meta-label">Content type</span>
                <span className="vt-meta-value">{attributes.content_type}</span>
              </div>
            )}
            {typeof analysisDate === "number" && (
              <div className="vt-meta-item">
                <span className="vt-meta-label">Última análise</span>
                <span className="vt-meta-value">
                  {new Date(analysisDate * 1000).toLocaleString("pt-BR")}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="vt-tabs">
        <button
          type="button"
          className={`vt-tab ${activeTab === "detection" ? "vt-tab-active" : ""}`}
          onClick={() => setActiveTab("detection")}
        >
          Detecção
        </button>
        <button
          type="button"
          className={`vt-tab ${activeTab === "details" ? "vt-tab-active" : ""}`}
          onClick={() => setActiveTab("details")}
        >
          Detalhes
        </button>
        <button
          type="button"
          className={`vt-tab ${activeTab === "community" ? "vt-tab-active" : ""}`}
          onClick={() => setActiveTab("community")}
        >
          Comunidade
        </button>
      </div>

      {activeTab === "detection" && (
        <div className="vt-detections">
          {engines.length === 0 ? (
            <p className="vt-empty">Nenhum resultado detalhado para exibir.</p>
          ) : (
            <table className="vt-table">
              <thead>
                <tr>
                  <th>Motor</th>
                  <th>Categoria</th>
                  <th>Resultado</th>
                  <th>Método</th>
                </tr>
              </thead>
              <tbody>
                {engines.map((engine, index) => (
                  <tr key={`${engine.engine_name ?? "engine"}-${index}`}>
                    <td>{engine.engine_name ?? "Desconhecido"}</td>
                    <td>{engine.category ?? "-"}</td>
                    <td>{engine.result ?? "clean"}</td>
                    <td>{engine.method ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === "details" && (
        <div className="vt-detections">
          <div className="vt-details-section">
            <h3>Categorias</h3>
            {Object.keys(categories).length === 0 ? (
              <p className="vt-empty">Nenhuma categoria disponível.</p>
            ) : (
              <ul className="vt-list">
                {Object.entries(categories as Record<string, string>).map(
                  ([vendor, category]) => (
                    <li key={vendor}>
                      <strong>{vendor}:</strong> {category}
                    </li>
                  )
                )}
              </ul>
            )}
          </div>

          <div className="vt-details-section">
            <h3>Histórico</h3>
            <ul className="vt-list">
              {typeof attributes.first_submission_date === "number" && (
                <li>
                  <strong>Primeira submissão:</strong>{" "}
                  {new Date(
                    attributes.first_submission_date * 1000
                  ).toLocaleString("pt-BR")}
                </li>
              )}
              {typeof attributes.last_submission_date === "number" && (
                <li>
                  <strong>Última submissão:</strong>{" "}
                  {new Date(
                    attributes.last_submission_date * 1000
                  ).toLocaleString("pt-BR")}
                </li>
              )}
              {typeof analysisDate === "number" && (
                <li>
                  <strong>Última análise:</strong>{" "}
                  {new Date(analysisDate * 1000).toLocaleString("pt-BR")}
                </li>
              )}
            </ul>
          </div>

          <div className="vt-details-section">
            <h3>Resumo técnico</h3>
            <ul className="vt-list">
              {mode === "url" &&
                typeof attributes.last_http_response_code === "number" && (
                  <li>
                    <strong>Status Code:</strong>{" "}
                    {attributes.last_http_response_code}
                  </li>
                )}
              {mode === "url" &&
                typeof attributes.last_http_response_content_type ===
                  "string" && (
                  <li>
                    <strong>Content type:</strong>{" "}
                    {attributes.last_http_response_content_type}
                  </li>
                )}
              <li>
                <strong>Harmless:</strong> {harmlessCount}
              </li>
              <li>
                <strong>Undetected:</strong> {undetectedCount}
              </li>
              <li>
                <strong>Timeout:</strong> {timeoutCount}
              </li>
            </ul>
          </div>
        </div>
      )}

      {activeTab === "community" && (
        <div className="vt-detections">
          <div className="vt-details-section">
            <h3>Comunidade</h3>
            <ul className="vt-list">
              {typeof reputation === "number" && (
                <li>
                  <strong>Reputação:</strong> {reputation}
                </li>
              )}
              {typeof totalVotes.harmless === "number" && (
                <li>
                  <strong>Votos harmless:</strong> {totalVotes.harmless}</li>
              )}
              {typeof totalVotes.malicious === "number" && (
                <li>
                  <strong>Votos maliciosos:</strong> {totalVotes.malicious}</li>
              )}
            </ul>
            <p className="vt-empty">
              Comentários detalhados da comunidade não são expostos pela API
              pública. Os números acima resumem a percepção de risco.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

export default function HomePage() {
  const [mode, setMode] = useState<Mode>("url");
  const [inputValue, setInputValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastQuery, setLastQuery] = useState<string>("");

  const modeDescription =
    mode === "url"
      ? "URL: envia o endereço informado para o VirusTotal, aguarda a análise e retorna o relatório completo da URL."
      : mode === "hash"
      ? "Arquivo (hash): consulta no VirusTotal um arquivo já conhecido a partir do seu hash (MD5, SHA1 ou SHA256)."
      : mode === "domain"
      ? "Domínio: busca informações de reputação e histórico de segurança relacionadas a um domínio (exemplo.com)."
      : mode === "ip"
      ? "IP: consulta o endereço IP e exibe dados de reputação, atividades suspeitas e associações conhecidas."
      : "Arquivo (upload): envia o arquivo selecionado para o VirusTotal para ser analisado pelos motores antivírus.";

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setResult(null);

    try {
      setLoading(true);

      if (mode === "file") {
        if (!file) {
          setError("Selecione um arquivo para analisar.");
          return;
        }

        const formData = new FormData();
        formData.append("file", file);

        setLastQuery(file.name);

        const response = await fetch("/api/vt", {
          method: "POST",
          body: formData
        });

        const data = (await response.json()) as any | ApiError;

        if (!response.ok || "error" in (data as ApiError)) {
          const message =
            "error" in (data as ApiError)
              ? (data as ApiError).error
              : "Erro ao consultar o VirusTotal.";
          setError(message);
          return;
        }

        setResult(data);
        return;
      }

      const value = inputValue.trim();
      if (!value) {
        setError("Preencha o campo antes de consultar.");
        return;
      }

      setLastQuery(value);

      const query = new URLSearchParams({
        type: mode,
        value
      });

      const response = await fetch(`/api/vt?${query.toString()}`);
      const data = (await response.json()) as any | ApiError;

      if (!response.ok || "error" in (data as ApiError)) {
        const message =
          "error" in (data as ApiError)
            ? (data as ApiError).error
            : "Erro ao consultar o VirusTotal.";
        setError(message);
        return;
      }

      setResult(data);
    } catch {
      setError("Erro de rede ao acessar o backend.");
    } finally {
      setLoading(false);
    }
  }

  function getSubmitLabel(currentMode: Mode) {
    switch (currentMode) {
      case "url":
        return "Analizar URL";
      case "hash":
        return "Analizar hash";
      case "domain":
        return "Analizar dominio";
      case "ip":
        return "Analizar IP";
      case "file":
      default:
        return "Analizar arquivo recebido";
    }
  }

  return (
    <main className="page">
      <section className="card">
        <header className="card-header">
          <h1>Analises de segurança</h1>
          <p>
            Consulte URLs, hashes de arquivos, domínios, IPs e envie arquivos
            para análise
          </p>
        </header>

        <div className="modes">
          <button
            type="button"
            className={`mode ${mode === "url" ? "mode-active" : ""}`}
            onClick={() => setMode("url")}
          >
            URL
          </button>
          <button
            type="button"
            className={`mode ${mode === "hash" ? "mode-active" : ""}`}
            onClick={() => setMode("hash")}
          >
            Arquivo (hash)
          </button>
          <button
            type="button"
            className={`mode ${mode === "domain" ? "mode-active" : ""}`}
            onClick={() => setMode("domain")}
          >
            Domínio
          </button>
          <button
            type="button"
            className={`mode ${mode === "ip" ? "mode-active" : ""}`}
            onClick={() => setMode("ip")}
          >
            IP
          </button>
          <button
            type="button"
            className={`mode ${mode === "file" ? "mode-active" : ""}`}
            onClick={() => setMode("file")}
          >
            Arquivo (upload)
          </button>
        </div>

        <p className="note">{modeDescription}</p>

        <form className="form" onSubmit={handleSubmit}>
          {mode !== "file" ? (
            <label className="label">
              {mode === "url"
                ? "URL para analisar"
                : mode === "hash"
                ? "Hash de arquivo (SHA256, SHA1 ou MD5)"
                : mode === "domain"
                ? "Domínio"
                : "Endereço IP"}
              <input
                className="input"
                type="text"
                value={inputValue}
                onChange={(event) => setInputValue(event.target.value)}
                placeholder={
                  mode === "url"
                    ? "https://exemplo.com"
                    : mode === "hash"
                    ? "d41d8cd98f00b204e9800998ecf8427e"
                    : mode === "domain"
                    ? "exemplo.com"
                    : "8.8.8.8"
                }
              />
            </label>
          ) : (
            <label className="label">
              Arquivo para enviar
              <input
                className="input"
                type="file"
                onChange={(event) =>
                  setFile(event.target.files ? event.target.files[0] : null)
                }
              />
            </label>
          )}

          <button className="button" type="submit" disabled={loading}>
            {loading ? "Consultando..." : getSubmitLabel(mode)}
          </button>
        </form>

        <div
          style={{
            marginTop: 24,
            textAlign: "center"
          }}
        >
          <hr
            style={{
              borderColor: "#2f2f38",
              marginBottom: 12
            }}
          />
          <p
            style={{
              margin: 0,
              fontSize: 12,
              color: "#ffffff"
            }}
          >
            Powered by Rafael Freitas
          </p>
        </div>
      </section>

      {!!error && (
        <section className="card card-error">
          <h2>Erro</h2>
          <p>{error}</p>
        </section>
      )}

      {!!result && (
        <VTResultCard mode={mode} result={result} queryLabel={lastQuery} />
      )}

      <footer className="footer" />
    </main>
  );
}

