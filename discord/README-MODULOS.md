# UpSysteM Discord — módulos funcionais

Separação lógica aplicada na v1.1.10:

- verification: template de verificação, captcha e concessão de cargo user.
- donation: botão DOAR, seleção com valores, sala temporária, modal, Pix, confirmação e key.
- logs: envio centralizado para DISCORD_LOG_CHANNEL_ID.
- keySupportTickets: painel Suporte Key, abertura/fechamento de ticket e transcript TXT.
- templates: payloads padronizados com logo e embeds escuros.
- permissions: cargos, botRoleId, dev/admin e overwrites de canal.

Nesta versão a separação foi estruturada por funções e documentação dentro da API atual para preservar compatibilidade com o deploy existente.
