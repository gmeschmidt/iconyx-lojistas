#!/usr/bin/env node
// Portal do Lojista ICONYX: gestão de acessos, conteúdo e build.
//
// Tudo o que vai para o repositório (público) fica criptografado (AES-GCM):
//   dados/conteudo.enc.json   "comum" (marca, textos gerais) cifrado com K0, e cada clube cifrado
//                             com a sua própria chave Kc. O nome do clube não aparece fora da cifra.
//   public/acessos.json       uma entrada por pessoa:
//       ct     → cifrado com usuário + senha (PBKDF2-SHA256): a chave pessoal U, nome e papel
//       adm    → cifrado com a chave de administração A: os mesmos dados + status e clubes liberados
//       grant  → cifrado com U: K0 e as chaves Kc dos clubes liberados (null = acesso desativado)
//   O lojista só consegue decifrar os clubes cujas chaves estão no seu grant.
//   O acesso de admin guarda A, K0 e todas as Kc, e é o que o painel de acessos usa.
//
// Comandos (credenciais de admin em ADMIN_USER / ADMIN_PASS):
//   node tools/portal.mjs add <usuario> "<Nome da loja>" [senha] [--clubes=id1,id2]
//   node tools/portal.mjs clubes <usuario> todos|id1,id2      define os clubes liberados
//   node tools/portal.mjs desativar|ativar <usuario>
//   node tools/portal.mjs senha <usuario> [nova]               redefine a senha (gera se omitida)
//   node tools/portal.mjs remove <usuario>
//   node tools/portal.mjs list
//   node tools/portal.mjs export [saida.json]                  decifra o conteúdo (padrão: conteudo.local.json)
//   node tools/portal.mjs import [entrada.json]                cifra de novo (cria chave para clube novo)
//   node tools/portal.mjs build                                gera dist/ e public/ (não precisa de senha)
//   node tools/portal.mjs migrate <usuarios.json>              converte o formato antigo (uma vez só)

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

const { subtle } = globalThis.crypto;
const getRandomValues = (a) => globalThis.crypto.getRandomValues(a);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const P = (...p) => join(ROOT, ...p);
const ACESSOS = P("public", "acessos.json");
const CONTEUDO = P("dados", "conteudo.enc.json");
const ITERS = 250000;
const ID_SALT = "iconyx-lojistas/id/v1:";
const REPO = "gmeschmidt/iconyx-lojistas";

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (u8) => Buffer.from(u8).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const rand = (n) => getRandomValues(new Uint8Array(n));
const hex = (n) => Buffer.from(rand(n)).toString("hex");
const newKey = () => b64(rand(32));
const normUser = (u) => String(u).trim().toLowerCase();

async function userId(user) {
  const h = await subtle.digest("SHA-256", enc.encode(ID_SALT + normUser(user)));
  return Buffer.from(h).toString("hex");
}
async function passKey(user, pass, salt, iters = ITERS) {
  const base = await subtle.importKey("raw", enc.encode(normUser(user) + "\n" + pass), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
const rawKey = (raw) => subtle.importKey("raw", unb64(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
async function seal(key, obj) {
  if (typeof key === "string") key = await rawKey(key);
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function open(key, box) {
  if (typeof key === "string") key = await rawKey(key);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
  return JSON.parse(dec.decode(pt));
}

const readJSON = (f) => JSON.parse(readFileSync(f, "utf8"));
const writeJSON = (f, o) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, JSON.stringify(o, null, 2) + "\n"); };
function genPass() {
  const abc = "abcdefghjkmnpqrstuvwxyz23456789";
  const r = rand(12);
  let s = "";
  for (let i = 0; i < 12; i++) s += abc[r[i] % abc.length] + (i % 4 === 3 && i < 11 ? "-" : "");
  return s;
}

// ---------- acessos ----------
// admin: { A, k0, clubes: { clubeId: { ref, k } } }
function grantFor(admin, clubes) {
  const ids = clubes === "todos" ? Object.keys(admin.clubes) : clubes.filter((id) => admin.clubes[id]);
  const out = {};
  for (const id of ids) out[admin.clubes[id].ref] = admin.clubes[id].k;
  return { k0: admin.k0, todos: clubes === "todos", clubes: out };
}
async function buildEntry({ usuario, senha, nome, papel, u, ativo, clubes, extra }, admin, old) {
  const e = old ? { ...old } : { id: await userId(usuario) };
  if (senha) {
    const salt = rand(16);
    const box = await seal(await passKey(usuario, senha, salt), { u, nome, papel, usuario: normUser(usuario), ...(extra || {}) });
    Object.assign(e, { salt: b64(salt), iters: ITERS, iv: box.iv, ct: box.ct });
  }
  e.adm = await seal(admin.A, { usuario: normUser(usuario), nome, papel, u, ativo, clubes, atualizado: new Date().toISOString().slice(0, 10) });
  e.grant = ativo ? await seal(u, grantFor(admin, clubes)) : null;
  return e;
}
async function adminUnlock(acessos) {
  const { ADMIN_USER: user, ADMIN_PASS: pass } = process.env;
  if (!user || !pass) throw new Error("Defina ADMIN_USER e ADMIN_PASS.");
  const id = await userId(user);
  const e = acessos.entradas.find((x) => x.id === id);
  if (!e) throw new Error("Usuário de admin não encontrado.");
  let r;
  try { r = await open(await passKey(user, pass, unb64(e.salt), e.iters), e); } catch { throw new Error("Senha de admin incorreta."); }
  if (r.papel !== "admin") throw new Error("Esse acesso não é de administrador.");
  return { ...r, entry: e, pass, user };
}
async function readUsers(acessos, admin) {
  const out = [];
  for (const e of acessos.entradas) out.push({ e, info: await open(admin.A, e.adm) });
  return out;
}
async function findUser(acessos, admin, usuario) {
  const id = await userId(usuario);
  const e = acessos.entradas.find((x) => x.id === id);
  if (!e) throw new Error("Usuário não encontrado: " + normUser(usuario));
  return { e, info: await open(admin.A, e.adm) };
}
// Regrava a entrada do admin (as chaves de clubes ficam dentro da caixa protegida pela senha dele).
async function saveAdminEntry(acessos, admin) {
  const info = await open(admin.A, admin.entry.adm);
  const ne = await buildEntry({ usuario: admin.user, senha: admin.pass, nome: info.nome, papel: "admin", u: admin.u, ativo: true, clubes: "todos",
    extra: { A: admin.A, k0: admin.k0, clubes: admin.clubes } }, admin, admin.entry);
  acessos.entradas = acessos.entradas.map((x) => (x.id === ne.id ? ne : x));
  admin.entry = ne;
}
function parseClubes(s) { return !s || s === "todos" ? "todos" : s.split(",").map((x) => x.trim()).filter(Boolean); }

// ---------- conteúdo ----------
async function sealContent(admin, content) {
  const { clubes, ...comum } = content;
  const out = { versao: 2, comum: await seal(admin.k0, comum), clubes: [] };
  for (const c of clubes) {
    if (!admin.clubes[c.id]) admin.clubes[c.id] = { ref: hex(6), k: newKey() };
    out.clubes.push({ ref: admin.clubes[c.id].ref, ...(await seal(admin.clubes[c.id].k, c)) });
  }
  return out;
}
async function openContent(admin) {
  const enc2 = readJSON(CONTEUDO);
  const comum = await open(admin.k0, enc2.comum);
  const byRef = Object.fromEntries(Object.entries(admin.clubes).map(([id, v]) => [v.ref, v.k]));
  const clubes = [];
  for (const b of enc2.clubes) clubes.push(await open(byRef[b.ref], b));
  return { ...comum, clubes };
}
// Atualiza os grants de quem tem "todos" (ex.: depois de entrar um clube novo).
async function refreshGrants(acessos, admin) {
  for (const { e, info } of await readUsers(acessos, admin)) {
    if (info.papel === "admin") continue;
    const ne = await buildEntry({ ...info }, admin, e);
    acessos.entradas = acessos.entradas.map((x) => (x.id === e.id ? ne : x));
  }
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const flags = Object.fromEntries(args.filter((a) => a.startsWith("--")).map((a) => a.slice(2).split("=")));
  const a = args.filter((x) => !x.startsWith("--"));
  switch (cmd) {
    case "migrate": {
      // usuarios.json: [{ usuario, senha, nome, papel?, clubes? }]; o admin vem de ADMIN_USER/ADMIN_PASS.
      const lista = readJSON(a[0]);
      const old = readJSON(P("dados", "acessos.json"));
      const { ADMIN_USER: user, ADMIN_PASS: pass } = process.env;
      const id = await userId(user);
      const ae = old.entradas.find((x) => x.id === id);
      const r = await open(await passKey(user, pass, unb64(ae.salt), ae.iters), ae);
      const content = await open(r.k, readJSON(CONTEUDO));
      const admin = { A: newKey(), k0: newKey(), clubes: {}, u: newKey(), user, pass };
      const conteudo = await sealContent(admin, content);
      const acessos = { versao: 2, entradas: [] };
      const ae2 = await buildEntry({ usuario: user, senha: pass, nome: "Administração ICONYX", papel: "admin", u: admin.u, ativo: true, clubes: "todos",
        extra: { A: admin.A, k0: admin.k0, clubes: admin.clubes } }, admin);
      acessos.entradas.push(ae2);
      for (const x of lista) {
        acessos.entradas.push(await buildEntry({ usuario: x.usuario, senha: x.senha, nome: x.nome, papel: x.papel || "lojista", u: newKey(), ativo: x.ativo !== false, clubes: x.clubes || "todos" }, admin));
      }
      writeJSON(CONTEUDO, conteudo);
      writeJSON(ACESSOS, acessos);
      console.log("Migrado:", acessos.entradas.length, "acessos,", conteudo.clubes.length, "clubes com chave própria.");
      break;
    }
    case "add": {
      const [user, nome, senha] = a;
      if (!user || !nome) throw new Error('Uso: node tools/portal.mjs add <usuario> "<Nome da loja>" [senha] [--clubes=id1,id2]');
      const acessos = readJSON(ACESSOS);
      const admin = await adminUnlock(acessos);
      const id = await userId(user);
      if (acessos.entradas.some((x) => x.id === id)) throw new Error("Esse usuário já existe.");
      const pass = senha || genPass();
      const clubes = parseClubes(flags.clubes);
      acessos.entradas.push(await buildEntry({ usuario: user, senha: pass, nome, papel: "lojista", u: newKey(), ativo: true, clubes }, admin));
      writeJSON(ACESSOS, acessos);
      console.log(`Lojista cadastrado\n  loja:    ${nome}\n  usuário: ${normUser(user)}\n  senha:   ${pass}\n  clubes:  ${clubes === "todos" ? "todos" : clubes.join(", ")}`);
      break;
    }
    case "clubes":
    case "ativar":
    case "desativar":
    case "senha": {
      const acessos = readJSON(ACESSOS);
      const admin = await adminUnlock(acessos);
      const { e, info } = await findUser(acessos, admin, a[0]);
      if (info.papel === "admin") throw new Error("Use outro caminho para mexer no acesso de admin.");
      let senha;
      if (cmd === "clubes") info.clubes = parseClubes(a[1]);
      if (cmd === "ativar") info.ativo = true;
      if (cmd === "desativar") info.ativo = false;
      if (cmd === "senha") senha = a[1] || genPass();
      const ne = await buildEntry({ ...info, senha }, admin, e);
      acessos.entradas = acessos.entradas.map((x) => (x.id === e.id ? ne : x));
      writeJSON(ACESSOS, acessos);
      console.log(`${info.usuario}: ${info.ativo ? "ativo" : "desativado"} · clubes: ${info.clubes === "todos" ? "todos" : info.clubes.join(", ")}${senha ? " · nova senha: " + senha : ""}`);
      break;
    }
    case "remove": {
      const acessos = readJSON(ACESSOS);
      const admin = await adminUnlock(acessos);
      const { e, info } = await findUser(acessos, admin, a[0]);
      if (info.papel === "admin") throw new Error("Não dá para remover o admin.");
      acessos.entradas = acessos.entradas.filter((x) => x.id !== e.id);
      writeJSON(ACESSOS, acessos);
      console.log("Acesso removido:", info.usuario);
      break;
    }
    case "list": {
      const acessos = readJSON(ACESSOS);
      const admin = await adminUnlock(acessos);
      for (const { info } of await readUsers(acessos, admin)) {
        console.log(`${info.papel === "admin" ? "[admin] " : ""}${info.usuario} · ${info.nome} · ${info.ativo ? "ativo" : "DESATIVADO"} · ${info.clubes === "todos" ? "todos os clubes" : info.clubes.join(", ")}`);
      }
      break;
    }
    case "export": {
      const out = a[0] || P("conteudo.local.json");
      const admin = await adminUnlock(readJSON(ACESSOS));
      writeJSON(out, await openContent(admin));
      console.log("Conteúdo decifrado em", out, "(não faça commit desse arquivo)");
      break;
    }
    case "import": {
      const src = a[0] || P("conteudo.local.json");
      const acessos = readJSON(ACESSOS);
      const admin = await adminUnlock(acessos);
      const n = Object.keys(admin.clubes).length;
      writeJSON(CONTEUDO, await sealContent(admin, readJSON(src)));
      if (Object.keys(admin.clubes).length !== n) {
        await saveAdminEntry(acessos, admin);
        await refreshGrants(acessos, admin);
        writeJSON(ACESSOS, acessos);
        console.log("Clube novo recebeu chave própria; acessos com 'todos' atualizados.");
      }
      console.log("Conteúdo cifrado em dados/conteudo.enc.json");
      break;
    }
    case "build": {
      const tpl = readFileSync(P("src", "portal.html"), "utf8");
      const logo = "data:image/png;base64," + readFileSync(P("src", "logo.png")).toString("base64");
      const logoDark = "data:image/png;base64," + readFileSync(P("src", "logo-dark.png")).toString("base64");
      let branch = "main";
      try { branch = execSync("git rev-parse --abbrev-ref HEAD", { cwd: ROOT }).toString().trim(); } catch {}
      const payload = JSON.stringify({ acessos: readJSON(ACESSOS), conteudo: readJSON(CONTEUDO), idSalt: ID_SALT, repo: REPO, branch, arquivoAcessos: "public/acessos.json" });
      const html = tpl.replaceAll("__LOGO_DARK__", logoDark).replaceAll("__LOGO__", logo).replace("__PAYLOAD__", () => payload.replace(/</g, "\\u003c"));
      mkdirSync(P("dist"), { recursive: true });
      writeFileSync(P("dist", "index.html"), html);
      console.log("dist/index.html gerado (" + Math.round(html.length / 1024) + " KB)");
      // Versão independente (Vercel ou qualquer hospedagem estática): documento HTML completo.
      const cut = html.indexOf("</style>") + "</style>".length;
      const site = [
        "<!doctype html>",
        '<html lang="pt-BR">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
        '<meta name="robots" content="noindex, nofollow">',
        '<link rel="icon" type="image/png" href="favicon.png">',
        "<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>",
        html.slice(0, cut),
        "</head>",
        "<body>",
        html.slice(cut),
        "</body>",
        "</html>",
        "",
      ].join("\n");
      writeFileSync(P("public", "index.html"), site);
      console.log("public/index.html gerado para hospedagem estática");
      // O Artifact não serve .glb: gera uma cópia em JSON (base64) só para a versão do Artifact.
      const walk = (dir) => (existsSync(dir) ? readdirSync(dir, { withFileTypes: true }) : []).flatMap((e) => e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]);
      for (const f of walk(P("public", "3d")).filter((f) => f.endsWith(".glb"))) {
        const rel = f.slice(P("public").length + 1);
        const out = P("dist", rel + ".json");
        mkdirSync(dirname(out), { recursive: true });
        writeFileSync(out, JSON.stringify({ glb: readFileSync(f).toString("base64") }));
      }
      break;
    }
    default:
      console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 26).join("\n"));
  }
}
main().catch((e) => { console.error("Erro:", e.message); process.exit(1); });
