# UpSysteM API v1.2.0 — PostgreSQL/Supabase

Esta API usa PostgreSQL via `DATABASE_URL`.

## Variáveis no Render

```txt
PORT=10000
JWT_SECRET=upsystem_btt7jvdsfJmt2rB9uOYOf3D7gyElqcO-_jg1FSYxN4sunys2w1s9bc2lgIm_YPdAStausWDi
ADMIN_USERNAME=admiro
ADMIN_PASSWORD=P4bl0_mur1l0
CORS_ORIGIN=*
DATABASE_URL=postgresql://postgres.SEUPROJETO:SUA_SENHA@aws-1-us-west-2.pooler.supabase.com:6543/postgres
```

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

Deve retornar:

```json
{
  "ok": true,
  "service": "UpSysteM API",
  "version": "1.2.0",
  "database": "postgresql"
}
```

## Migração

1. Na versão antiga, exporte o TXT em Console > Exportação.
2. Suba esta API v1.2.0 no Render.
3. Configure `DATABASE_URL`.
4. Faça deploy.
5. Instale/abra a extensão.
6. Importe o TXT em Console > Exportação.
