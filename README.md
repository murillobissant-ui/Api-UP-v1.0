# UpSysteM API v2.1.0 BUILD003

API online oficial do projeto UpSysteM, usada pelo Console DEV, pela extensão e pelas integrações Discord/Mercado Pago.

Esta versão usa o BUILD obrigatório:

```env
REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-003
```

## Estado da versão

- Versão pública/API: `2.1.0`
- Build obrigatório: `BUILD003`
- Base funcional: v2.0.39 atualizada
- Console DEV: online via API/Render
- Admin local/fallback `admin/admin123`: removido
- Discord.js: evento `clientReady`
- Dados de computador/vínculo: ocultos por padrão no Console

## Autenticação Admin centralizada no Render

O login administrativo principal é controlado pelas variáveis do Render:

```env
ADMIN_USERNAME=seu_admin
ADMIN_PASSWORD=sua_senha_segura
```

Ao alterar essas variáveis no Render e executar redeploy/restart, a API sincroniza o usuário `admin-root` com os novos dados.

Regras:

- o Render/API é a fonte única do Admin;
- não usar credencial fixa local;
- não usar fallback `admin/admin123`;
- sessões antigas podem expirar quando usuário/senha forem alterados;
- variantes DEV/USUARIO/PARCEIRO devem consultar a API, quando aplicável.

## Variáveis principais no Render

```env
PORT=10000
JWT_SECRET=troque-por-uma-chave-grande-e-secreta
ADMIN_USERNAME=admiro
ADMIN_PASSWORD=troque-essa-senha
CORS_ORIGIN=*
DATABASE_URL=postgresql://postgres.SEUPROJETO:SUA_SENHA@aws-1-us-west-2.pooler.supabase.com:6543/postgres
MIN_EXTENSION_VERSION=2.1.0
REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-003
UPSYSTEM_PUBLIC_VERSION=2.1.0
UPSYSTEM_EXTENSION_ONLINE_WINDOW_MINUTES=30
UPSYSTEM_EXTENSION_HEARTBEAT_INTERVAL_MINUTES=30
MAX_LOGS=500
LOG_RETENTION_DAYS=7
MAX_SYSTEM_LOGS=100
SYSTEM_LOG_RETENTION_DAYS=7
```

## Discord

```env
DISCORD_ENABLED=true
DISCORD_LOG_CHANNEL_ID=1501406205845835796
DISCORD_TICKET_LOG_CHANNEL_ID=1501759453199073400
DISCORD_VERIFY_CHANNEL_ID=1501417052638937240
DISCORD_ROLE_USER_ID=1501475029416677417
DISCORD_ROLE_CLIENTES_ID=1501465629264318484
DISCORD_BOT_ROLE_ID=1501405803301572741
DISCORD_ROLE_DEV_ID=1501465600600444998
DISCORD_ROLE_ADMIRO_ID=1501474309124919459
DISCORD_ROLE_PARCEIRO_ID=1501465651842121809
DISCORD_TICKET_CATEGORY_ID=1501405325201248326
DISCORD_TICKET_PANEL_CHANNEL_ID=
DISCORD_SUPPORT_URL=https://discord.gg/seu-convite
```

O bot deve usar `clientReady` no Discord.js para evitar o aviso de depreciação do evento `ready`.

## Doação / Mercado Pago

```env
MERCADOPAGO_ENABLED=true
MERCADOPAGO_MODE=production
MERCADOPAGO_NOTIFICATION_URL=https://api-up-v1-0.onrender.com/webhooks/mercadopago?source_news=webhooks
PAYPAL_ENABLED=false
UPSYSTEM_DONATION_POLL_INTERVAL_SECONDS=10
UPSYSTEM_DONATION_POLL_TIMEOUT_MINUTES=5
```

Comunicação pública deve usar linguagem de doação: doação, contribuir, apoiador, plano de doação e key de acesso.

## Mensagens temporárias e limpeza

```env
DISCORD_VALIDATION_DELETE_AFTER_DM_SECONDS=30
DISCORD_VALIDATION_DELETE_AFTER_CHANNEL_KEY_MINUTES=10
DISCORD_EPHEMERAL_SUCCESS_TTL_SECONDS=5
DISCORD_EPHEMERAL_ERROR_TTL_SECONDS=10
DISCORD_CAPTCHA_TTL_MINUTES=2
DISCORD_CLEAR_FEEDBACK_TTL_SECONDS=5
DISCORD_PAYPAL_SOON_TTL_SECONDS=8
DISCORD_PLAN_SELECT_FEEDBACK_TTL_SECONDS=5
```

## Comandos Render

```txt
Build Command: npm install
Start Command: npm start
```

## Health check

```txt
GET /health
```

Resposta esperada:

```json
{
  "ok": true,
  "service": "UpSysteM API",
  "version": "2.1.0"
}
```

## Console DEV

O Console DEV deve operar em escala própria de navegador normal, sem herdar tamanho de popup da extensão.

Regras atuais:

- abas Usuários e Keys com menus `...` ocultos por padrão;
- menus aparecem somente após clique;
- clique fora fecha o menu;
- dados de cliente e computador vinculado ficam ocultos por padrão;
- botão `Renovar` renova a key a partir da data do clique conforme plano atual;
- lista de Usuários deve manter área ampla e alinhada como a aba Keys.

## Logs

A API mantém logs operacionais e logs do sistema com retenção controlada por quantidade e dias.

- `MAX_LOGS`
- `LOG_RETENTION_DAYS`
- `MAX_SYSTEM_LOGS`
- `SYSTEM_LOG_RETENTION_DAYS`

## Segurança

Nunca expor no chat, README público ou commit:

- `DISCORD_BOT_TOKEN`
- `MERCADOPAGO_ACCESS_TOKEN`
- `MERCADOPAGO_WEBHOOK_SECRET`
- `PAYPAL_CLIENT_SECRET`
- qualquer token, secret, senha ou chave privada real.

## Observação

Esta v2.1.0 é uma atualização documental/versionamento sobre a base funcional v2.0.39 enviada pelo usuário.
Código funcional preservado, salvo ajustes textuais de versão solicitados.
