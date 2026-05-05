# UpSysteM API Online v4.2

API online para centralizar usuários, keys, planos, permissões, parceiros, limites, sites e logs da extensão UpSysteM.

## Rodar local

```bash
cd upsystem-api
npm install
cp .env.example .env
npm start
```

A API ficará em:

```txt
http://localhost:10000
```

## Deploy no Render

1. Crie um novo Web Service no Render.
2. Suba esta pasta `upsystem-api` para um repositório GitHub.
3. Configure:
   - Build Command: `npm install`
   - Start Command: `npm start`
4. Configure as variáveis de ambiente:
   - `PORT=10000`
   - `JWT_SECRET=upsystem_btt7jvdsfJmt2rB9uOYOf3D7gyElqcO-_jg1FSYxN4sunys2w1s9bc2lgIm_YPdAStausWDi
   - `ADMIN_USERNAME=admiro`
   - `ADMIN_PASSWORD=P4bl0_mur1l0`
   - `CORS_ORIGIN=*`
   - `DATA_FILE=./data/db.json`

## Observação

Esta primeira versão online usa arquivo JSON como banco inicial para facilitar o deploy e os testes.
Para produção com muitos clientes, o ideal é migrar para PostgreSQL/Supabase.


## Admin padrão deste pacote

```txt
ADMIN_USERNAME=admiro
ADMIN_PASSWORD=P4bl0_mur1l0
```

Se o banco antigo já tiver sido criado, altere também o `DATA_FILE`, por exemplo:

```txt
DATA_FILE=./data/db-v4.json
```


## JWT_SECRET gerada para este pacote

```txt
JWT_SECRET=upsystem_btt7jvdsfJmt2rB9uOYOf3D7gyElqcO-_jg1FSYxN4sunys2w1s9bc2lgIm_YPdAStausWDi
```
