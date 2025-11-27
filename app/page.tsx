"use client";

import { FormEvent, useState } from "react";

type Mode = "url" | "hash" | "domain" | "ip" | "file";

type VTResponse = unknown;

type ApiError = {
  error: string;
};

export default function HomePage() {
  const [mode, setMode] = useState<Mode>("url");
  const [inputValue, setInputValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VTResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

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

        const response = await fetch("/api/vt", {
          method: "POST",
          body: formData
        });

        const data = (await response.json()) as VTResponse | ApiError;

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

      const query = new URLSearchParams({
        type: mode,
        value
      });

      const response = await fetch(`/api/vt?${query.toString()}`);
      const data = (await response.json()) as VTResponse | ApiError;

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

  return (
    <main className="page">
      <section className="card">
        <header className="card-header">
          <h1>Painel VirusTotal</h1>
          <p>
            Consulte URLs, hashes de arquivos, domínios, IPs e envie arquivos
            para análise usando a sua API key do VirusTotal.
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
            {loading ? "Consultando..." : "Consultar no VirusTotal"}
          </button>
        </form>

        <p className="note">
          <strong>Atenção:</strong> este painel usa a sua própria API key do
          VirusTotal (configurada via variável de ambiente). Respeite os termos
          de uso da plataforma e a privacidade dos arquivos enviados.
        </p>
      </section>

      {!!error && (
        <section className="card card-error">
          <h2>Erro</h2>
          <p>{error}</p>
        </section>
      )}

      {!!result && (
        <section className="card card-result">
          <header className="card-header">
            <h2>Resposta do VirusTotal</h2>
          </header>
          <div className="result-section">
            <pre className="json">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        </section>
      )}

      <footer className="footer">
        <p>Powered by Rafael Freitas</p>
      </footer>
    </main>
  );
}
