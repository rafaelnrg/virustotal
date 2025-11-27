import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Painel VirusTotal",
  description:
    "Console simples para consultar URLs, arquivos, domínios e IPs usando a API do VirusTotal."
};

export default function RootLayout(props: { children: ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>{props.children}</body>
    </html>
  );
}

