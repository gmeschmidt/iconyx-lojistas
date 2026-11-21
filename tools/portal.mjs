#!/usr/bin/env node
// Portal do Lojista ICONYX: gestão de acessos, conteúdo e build.
//
// Tudo o que vai para o repositório (público) fica criptografado:
//   dados/conteudo.enc.json  conteúdo (textos, clubes, links) cifrado com AES-GCM pela chave K
//   dados/acessos.json       uma entrada por pessoa; cada uma guarda K cifrada com uma chave
//                            derivada de usuário + senha (PBKDF2-SHA256). Sem usuário e senha
//                            válidos não dá para ler nada, nem o nome da loja.
// A senha de administrador é só um acesso a mais, usado aqui para destrancar K.
//
// Comandos (credenciais de admin em ADMIN_USER / ADMIN_PASS):
//   node tools/portal.mjs init <arquivo.json>             cria K, o acesso de admin e cifra o conteúdo
//   node tools/portal.mjs add <usuario> "<Nome da loja>" [senha]   cadastra lojista (gera senha se omitida)
//   node tools/portal.mjs remove <usuario>                remove um acesso
//   node tools/portal.mjs export [saida.json]             decifra o conteúdo para editar (padrão: conteudo.local.json)
//   node tools/portal.mjs import [entrada.json]           cifra de novo o conteúdo editado
//   node tools/portal.mjs build                           gera dist/index.html (não precisa de senha)

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { subtle } = globalThis.crypto;
const getRandomValues = (a) => globalThis.crypto.getRandomValues(a);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const P = (...p) => join(ROOT, ...p);
const ACESSOS = P("dados", "acessos.json");
const CONTEUDO = P("dados", "conteudo.enc.json");
const ITERS = 250000;
const ID_SALT = "iconyx-lojistas/id/v1:";

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (u8) => Buffer.from(u8).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const rand = (n) => getRandomValues(new Uint8Array(n));
const normUser = (u) => String(u).trim().toLowerCase();

async function userId(user) {
  const h = await subtle.digest("SHA-256", enc.encode(ID_SALT + normUser(user)));
  return Buffer.from(h).toString("hex");
}
async function passKey(user, pass, salt) {
  const base = await subtle.importKey("raw", enc.encode(normUser(user) + "\n" + pass), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERS, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(key, obj) {
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function open(key, box) {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct));
  return JSON.parse(dec.decode(pt));
}
const contentKey = (raw) => subtle.importKey("raw", unb64(raw), "AES-GCM", false, ["encrypt", "decrypt"]);

async function makeEntry(user, pass, nome, papel, kRaw) {
  const salt = rand(16);
  const key = await passKey(user, pass, salt);
  return { id: await userId(user), salt: b64(salt), iters: ITERS, ...(await seal(key, { k: kRaw, nome, papel, usuario: normUser(user) })) };
}
async function unlock(user, pass, acessos) {
  const id = await userId(user);
  const e = acessos.entradas.find((x) => x.id === id);
  if (!e) throw new Error("Usuário não encontrado.");
  try { return await open(await passKey(user, pass, unb64(e.salt)), e); }
  catch { throw new Error("Senha incorreta."); }
}
async function adminUnlock(acessos) {
  const { ADMIN_USER: u, ADMIN_PASS: p } = process.env;
  if (!u || !p) throw new Error("Defina ADMIN_USER e ADMIN_PASS.");
  const r = await unlock(u, p, acessos);
  if (r.papel !== "admin") throw new Error("Esse acesso não é de administrador.");
  return r;
}
function genPass() {
  const abc = "abcdefghjkmnpqrstuvwxyz23456789";
  const r = rand(12);
  let s = "";
  for (let i = 0; i < 12; i++) s += abc[r[i] % abc.length] + (i % 4 === 3 && i < 11 ? "-" : "");
  return s;
}
const readJSON = (f) => JSON.parse(readFileSync(f, "utf8"));
const writeJSON = (f, o) => writeFileSync(f, JSON.stringify(o, null, 2) + "\n");
const loadAcessos = () => readJSON(ACESSOS);

async function main() {
  const [cmd, ...a] = process.argv.slice(2);
  switch (cmd) {
    case "init": {
      if (existsSync(ACESSOS)) throw new Error("dados/acessos.json já existe. Apague-o para reiniciar.");
      const { ADMIN_USER: u, ADMIN_PASS: p } = process.env;
      if (!u || !p || !a[0]) throw new Error("Uso: ADMIN_USER=.. ADMIN_PASS=.. node tools/portal.mjs init conteudo.json");
      const kRaw = b64(rand(32));
      const acessos = { versao: 1, entradas: [await makeEntry(u, p, "Administração ICONYX", "admin", kRaw)] };
      mkdirSync(P("dados"), { recursive: true });
      writeJSON(ACESSOS, acessos);
      writeJSON(CONTEUDO, await seal(await contentKey(kRaw), readJSON(a[0])));
      console.log("Portal iniciado. Acesso de admin criado para", normUser(u));
      break;
    }
    case "add": {
      const [user, nome, senha] = a;
      if (!user || !nome) throw new Error('Uso: node tools/portal.mjs add <usuario> "<Nome da loja>" [senha]');
      const acessos = loadAcessos();
      const { k } = await adminUnlock(acessos);
      const id = await userId(user);
      if (acessos.entradas.some((x) => x.id === id)) throw new Error("Esse usuário já existe. Remova antes de recriar.");
      const pass = senha || genPass();
      acessos.entradas.push(await makeEntry(user, pass, nome, "lojista", k));
      writeJSON(ACESSOS, acessos);
      console.log(`Lojista cadastrado\n  loja:    ${nome}\n  usuário: ${normUser(user)}\n  senha:   ${pass}`);
      break;
    }
    case "remove": {
      if (!a[0]) throw new Error("Uso: node tools/portal.mjs remove <usuario>");
      const acessos = loadAcessos();
      await adminUnlock(acessos);
      const id = await userId(a[0]);
      const n = acessos.entradas.length;
      acessos.entradas = acessos.entradas.filter((x) => x.id !== id);
      if (acessos.entradas.length === n) throw new Error("Usuário não encontrado.");
      writeJSON(ACESSOS, acessos);
      console.log("Acesso removido:", normUser(a[0]));
      break;
    }
    case "export": {
      const out = a[0] || P("conteudo.local.json");
      const { k } = await adminUnlock(loadAcessos());
      writeJSON(out, await open(await contentKey(k), readJSON(CONTEUDO)));
      console.log("Conteúdo decifrado em", out, "(não faça commit desse arquivo)");
      break;
    }
    case "import": {
      const src = a[0] || P("conteudo.local.json");
      const { k } = await adminUnlock(loadAcessos());
      writeJSON(CONTEUDO, await seal(await contentKey(k), readJSON(src)));
      console.log("Conteúdo cifrado em dados/conteudo.enc.json");
      break;
    }
    case "build": {
      const tpl = readFileSync(P("src", "portal.html"), "utf8");
      const logo = "data:image/png;base64," + readFileSync(P("src", "logo.png")).toString("base64");
      const payload = JSON.stringify({ acessos: loadAcessos(), conteudo: readJSON(CONTEUDO), idSalt: ID_SALT });
      const html = tpl.replaceAll("__LOGO__", logo).replace("__PAYLOAD__", () => payload.replace(/</g, "\\u003c"));
      mkdirSync(P("dist"), { recursive: true });
      writeFileSync(P("dist", "index.html"), html);
      console.log("dist/index.html gerado (" + Math.round(html.length / 1024) + " KB)");
      break;
    }
    default:
      console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 20).join("\n"));
  }
}
main().catch((e) => { console.error("Erro:", e.message); process.exit(1); });
