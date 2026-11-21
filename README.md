# Portal do Lojista ICONYX

Página com login por lojista que reúne as descrições de produto (com botão de copiar), o filtro por clube e o link do banco de imagens no Zoho WorkDrive.

Este repositório é público, então nada fica em texto aberto: o conteúdo (`dados/conteudo.enc.json`) é cifrado com AES-GCM e cada acesso em `dados/acessos.json` guarda a chave do conteúdo cifrada com usuário e senha (PBKDF2-SHA256, 250 mil iterações). Sem um login válido não dá para ler os textos, o link do WorkDrive nem o nome das lojas.

## Comandos

As credenciais de administrador vão em `ADMIN_USER` e `ADMIN_PASS`.

```bash
node tools/portal.mjs add <usuario> "<Nome da loja>" [senha]   # cadastra lojista (gera senha se omitida)
node tools/portal.mjs remove <usuario>                         # remove acesso
node tools/portal.mjs export                                   # decifra para conteudo.local.json (fora do git)
node tools/portal.mjs import                                   # cifra o conteudo.local.json editado
node tools/portal.mjs build                                    # gera dist/index.html
```

`dist/index.html` é o arquivo publicado como Artifact.
