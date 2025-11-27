# Painel VirusTotal

Aplicação Next.js para consultar recursos da API do [VirusTotal](https://virustotal.com) usando sua própria API key.

Recursos implementados:

- Análise de **URLs** (envio + polling do resultado da análise).
- Consulta por **hash de arquivo** (`/files/{hash}`).
- Consulta de **domínio** (`/domains/{domain}`).
- Consulta de **endereço IP** (`/ip_addresses/{ip}`).
- **Envio de arquivos** para análise (`/files`).

> Importante: **não** deixe a sua API key exposta no código ou em commits. Use variáveis de ambiente.

## Configuração

1. Copie o arquivo `.env.local.example` para `.env.local`:

```bash
cp .env.local.example .env.local
```

2. Edite `.env.local` e informe a sua API key do VirusTotal:

```bash
VIRUSTOTAL_API_KEY=SEU_TOKEN_AQUI
```

3. Instale as dependências e rode localmente:

```bash
npm install
npm run dev
```

4. Abra em `http://localhost:3000`.

## Deploy na Vercel

1. Crie um novo projeto na Vercel apontando para esta pasta `virustotal`.
2. Em **Environment Variables** da Vercel, adicione:

   - `VIRUSTOTAL_API_KEY` = `SEU_TOKEN_AQUI`

3. A Vercel detecta automaticamente o Next.js e usa `npm run build` / `npm start`.
4. Após o deploy, você poderá acessar o painel e consultar o VirusTotal direto do navegador.

