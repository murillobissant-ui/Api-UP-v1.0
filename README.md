# UpSysteM API v1.0.2 — PostgreSQL/Supabase

Esta API usa PostgreSQL/Supabase via `DATABASE_URL` e centraliza a validação da extensão, usuários, keys, sites e logs.

## Variáveis no Render

```txt
PORT=10000
JWT_SECRET=troque-por-uma-chave-grande-e-secreta
ADMIN_USERNAME=admiro
ADMIN_PASSWORD=troque-essa-senha
CORS_ORIGIN=*
DATABASE_URL=postgresql://postgres.SEUPROJETO:SUA_SENHA@aws-1-us-west-2.pooler.supabase.com:6543/postgres
MIN_EXTENSION_VERSION=1.0.2
REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-002
MAX_LOGS=500
LOG_RETENTION_DAYS=7
```

## Logs

A partir da v1.0.2, a API mantém as logs sob duas regras simultâneas:

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
  "version": "1.0.2",
  "database": "postgresql"
}
```

## Logs do Sistema
A partir da v1.0.2, os erros técnicos são separados dos ciclos operacionais.

Variáveis opcionais:

```env
MAX_SYSTEM_LOGS=100
SYSTEM_LOG_RETENTION_DAYS=7
```

A API cria a tabela `upsystem_system_logs` automaticamente no PostgreSQL/Supabase.


### Bloqueio por build da extensão

Use `REQUIRED_EXTENSION_BUILD=upsystem-v1-cleanbase-002` no Render para bloquear versões antigas mesmo quando a numeração da versão for reduzida. A extensão DEV v1.0.2 envia o header `X-UpSystem-Build` em todas as chamadas online.

## Atualização v1.0.2

- Exclusão em cascata controlada: ao excluir usuário pelo ADM, a API remove keys vinculadas/resgatadas por ele.
- Reparação automática de keys órfãs: ao consultar keys, registros vinculados a usuários inexistentes são marcados como `inactive` com motivo administrativo.
- Nova permissão interna `discord_integration`, reservada ao ADM para aba futura de Discord no Console.
