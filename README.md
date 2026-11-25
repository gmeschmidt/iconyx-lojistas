# Portal do Lojista ICONYX

Página com login por lojista que reúne as descrições de produto (com botão de copiar), o filtro por clube e o link do banco de imagens no Zoho WorkDrive.

Este repositório é público, então nada fica em texto aberto: o conteúdo (`dados/conteudo.enc.json`) é cifrado com AES-GCM e cada acesso em `dados/acessos.json` guarda a chave do conteúdo cifrada com usuário e senha (PBKDF2-SHA256, 250 mil iterações). Sem um login válido não dá para ler os textos, o link do WorkDrive nem o nome das lojas.

## Como a proteção funciona

O conteúdo comum (marca e textos gerais) tem uma chave, e cada clube tem a sua própria chave. Em `public/acessos.json`, cada lojista recebe só as chaves dos clubes liberados para ele, cifradas com a chave pessoal dele, que por sua vez é aberta com usuário e senha. Quem não tem a chave de um clube não consegue ler esse clube, nem pelo código da página.

## Painel de acessos (admin)

Ao entrar com o acesso de administrador, aparece **Gerenciar acessos** no topo. Lá dá para ativar e desativar lojas, escolher os clubes de cada uma, gerar nova senha, remover e cadastrar lojistas. **Publicar alterações** grava `public/acessos.json` direto no GitHub (precisa de um token fine-grained com Contents: Read and write neste repositório) e a Vercel publica em cerca de um minuto.

Como o painel grava no repositório, faça `git pull` antes de mexer nos acessos pela linha de comando.

## Comandos

As credenciais de administrador vão em `ADMIN_USER` e `ADMIN_PASS`.

```bash
node tools/portal.mjs add <usuario> "<Nome da loja>" [senha] [--clubes=coritiba,palmeiras]
node tools/portal.mjs clubes <usuario> todos|coritiba,palmeiras
node tools/portal.mjs desativar|ativar <usuario>
node tools/portal.mjs senha <usuario> [nova]
node tools/portal.mjs remove <usuario>
node tools/portal.mjs list
node tools/portal.mjs export        # decifra para conteudo.local.json (fora do git)
node tools/portal.mjs import        # cifra o conteudo.local.json editado
node tools/portal.mjs build         # gera dist/ (Artifact) e public/ (Vercel)
```

`dist/index.html` é o arquivo publicado como Artifact. `public/` é a versão para hospedagem estática (Vercel): o `build` também gera `public/index.html`, e o `vercel.json` aponta para essa pasta, sem etapa de build.

As fotos dos produtos ficam em `public/img/<clube>/<produto>.webp` (fotos públicas, já exibidas nas landing pages). Ao publicar como Artifact, essas imagens vão junto como arquivos `img/...`.
