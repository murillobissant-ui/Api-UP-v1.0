# UpSysteM API v1.0.8 — PostgreSQL/Supabase

Esta API usa PostgreSQL/Supabase via `DATABASE_URL` e centraliza a validação da extensão, usuários, keys, sites e logs.

## Variáveis no Render

```txt
PORT=10000
JWT_SECRET=troque-por-uma-chave-grande-e-secreta
ADMIN_USERNAME=admiro
ADMIN_PASSWORD=troque-essa-senha
CORS_ORIGIN=*
DATABASE_URL=postgresql://postgres.SEUPROJETO:SUA_SENHA@aws-1-us-west-2.pooler.supabase.com:6543/postgres
MIN_EXTENSION_VERSION=1.0.8
REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-003
MAX_LOGS=500
LOG_RETENTION_DAYS=7
```

## Logs

A partir da v1.0.8, a API mantém as logs sob duas regras simultâneas:

- no máximo `MAX_LOGS` registros, padrão `500`;
- retenção máxima de `LOG_RETENTION_DAYS` dias, padrão `7`.

Quando novas logs são gravadas, a API remove automaticamente as logs antigas e mantém apenas as mais recentes dentro desses limites.

`DATA_FILE` não é mais usado nesta versão.

## Comandos Render

```txt
Build Command: npm install
Start Command: npm start
```

## Health check

```txt
/health
```

Deve retornar algo semelhante a:

```json
{
  "ok": true,
  "service": "UpSysteM API",
  "version": "1.0.8",
  "database": "postgresql"
}
```

## Logs do Sistema
A partir da v1.0.8, os erros técnicos são separados dos ciclos operacionais.

Variáveis opcionais:

```env
MAX_SYSTEM_LOGS=100
SYSTEM_LOG_RETENTION_DAYS=7
```

A API cria a tabela `upsystem_system_logs` automaticamente no PostgreSQL/Supabase.


### Bloqueio por build da extensão

Use `REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-003` no Render para bloquear versões antigas mesmo quando a numeração da versão for reduzida. A extensão DEV v1.0.8 envia o header `X-UpSystem-Build` em todas as chamadas online.

## Atualização v1.0.8

- Exclusão em cascata controlada: ao excluir usuário pelo ADM, a API remove keys vinculadas/resgatadas por ele.
- Reparação automática de keys órfãs: ao consultar keys, registros vinculados a usuários inexistentes são marcados como `inactive` com motivo administrativo.
- Nova permissão interna `discord_integration`, reservada ao ADM para aba futura de Discord no Console.

## Discord - preparação v1.0.8 BUILD003

Variáveis esperadas no Render:

```env
DISCORD_ENABLED=false
DISCORD_CLIENT_ID=1501402366828875796
DISCORD_GUILD_ID=1501405324492673184
DISCORD_SALES_CHANNEL_ID=1501406249877766226
DISCORD_LOG_CHANNEL_ID=1501406205845835796
DISCORD_BOT_TOKEN=cole-o-token-apenas-no-render
```

A rota `GET /discord/status` valida a presença das variáveis e informa o status ao Console sem exibir o token do bot.

## Pagamentos - preparação Fase 1 e Fase 2 v1.0.8 BUILD003

Estrutura preparada para Mercado Pago e PayPal, sem entrega automática de key nesta versão.

Variáveis futuras no Render:

```env
MERCADOPAGO_ENABLED=false
MERCADOPAGO_ACCESS_TOKEN=
MERCADOPAGO_WEBHOOK_SECRET=
MERCADOPAGO_MODE=production
MERCADOPAGO_NOTIFICATION_URL=https://api-up-v1-0.onrender.com/webhooks/mercadopago
PAYPAL_ENABLED=false
PAYPAL_CLIENT_ID=
PAYPAL_CLIENT_SECRET=
PAYPAL_WEBHOOK_ID=
PAYPAL_MODE=sandbox
```

Rotas preparadas:

- `GET /payments/status`
- `GET /discord/orders`
- `POST /discord/orders`
- `POST /webhooks/mercadopago`
- `POST /webhooks/paypal`

Fase 3 permanece aguardando: Stripe, Paddle e Lemon Squeezy.

ATUALIZAÇÃO v1.0.8 BUILD003:
- Corrigida restauração de último clique, próximo clique e tempo restante após fechar/deslogar/logar.
- Cronômetro operacional agora é lido do storage persistente por usuário + site.
- Logs operacionais repetidas são deduplicadas em janela curta para reduzir ruído.
- Build obrigatório permanece upsystem-v1-cleanbase-003.
