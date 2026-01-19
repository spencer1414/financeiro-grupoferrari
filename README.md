# Financeiro Rede (multi-lojas)

Sistema web para **gestão de contas a pagar** de uma rede de lojas.

> Este projeto foi feito para ser **fácil de subir rápido**: banco em arquivo JSON + anexos em pasta.
> Quando você quiser evoluir, dá para migrar para PostgreSQL/MySQL sem mudar o uso do sistema.

## Perfis
- **ADMIN**: cadastra lojas e usuários, vê tudo.
- **OWNER (Patrão)**: vê tudo de forma consolidada.
- **MANAGER (Gerente de loja)**: vê e cadastra contas **apenas da sua loja**.

## Funcionalidades
- Cadastro de lojas ilimitadas
- Login por e-mail e senha (sessão)
- Cadastro de contas a pagar com:
  - Nome do débito
  - Motivo/descrição
  - Valor (opcional)
  - Vencimento
  - Método: Boleto / Pix / Outro
  - Código de barras (boleto)
  - Chave Pix
  - Flag **Débito do dia (urgente)**
  - Anexo (boleto/nota fiscal)
- Painel do Patrão com organização:
  - **Vence hoje**
  - **Próximos 2 dias**
  - Até 5 / 10 / 15 / 30 / 60 dias
  - Vencidas
- Baixa (marcar como PAGO)
- Histórico mensal
- Exportação **Excel (.xlsx)** por mês

## Onde ficam os dados
- Banco: `./data/db.json`
- Anexos: `./src/uploads/`

## Como rodar (local)
1) Instale Node.js (>= 18)
2) No terminal:

```bash
npm install
cp .env.example .env
npm run start
```

Acesse: `http://localhost:3000`

### Primeiro acesso (Admin)
- Se o banco estiver vazio, o sistema cria um Admin inicial.
- Você pode definir no `.env`:
  - `SEED_ADMIN_EMAIL`
  - `SEED_ADMIN_PASSWORD`

> Se você não configurar SMTP, os convites de login criados pelo Admin serão mostrados no terminal como **EMAIL SIMULADO**.

## Como publicar (online)
Você pode publicar em um VPS/servidor Linux ou em plataformas como Render/Railway.

**Importante:**
- Faça backup regular de `./data/db.json`.
- Faça backup também de `./src/uploads/` (boletos e notas).

### VPS (exemplo rápido)
- Suba o projeto
- Configure `.env` com `BASE_URL` do seu domínio
- Rode em produção com um gerenciador de processo (ex.: PM2)

## Segurança (boas práticas)
- Troque `SESSION_SECRET`.
- Use HTTPS no domínio.
- Configure SMTP para convites por e-mail.

## Próximos upgrades (se você quiser evoluir)
- Aprovação de pagamento (dupla checagem)
- Centro de custo / categorias
- Relatórios por fornecedor
- Permissões mais granulares (ex.: gerente cadastra, mas só patrão dá baixa)
- Logs/auditoria (quem editou/pagou)
- Lembretes automáticos por WhatsApp/e-mail
- Migração do banco para PostgreSQL
