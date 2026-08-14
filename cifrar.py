#!/usr/bin/env python3
"""
Cifra fuente/nota-en-claro.html y genera el index.html publicable.

AES-256-GCM + PBKDF2-SHA256 (200.000 iteraciones), el esquema del
Panel de Proyectos Publicados. La clave NO se escribe en ningun archivo
del repo: se pide por consola.

Uso:   python3 cifrar.py
"""
import base64
import getpass
import gzip
import json
import os
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("Falta la libreria: pip3 install cryptography --break-system-packages")

RAIZ = Path(__file__).resolve().parent
ORIGEN = RAIZ / "fuente" / "nota-en-claro.html"
DESTINO = RAIZ / "index.html"
ITERACIONES = 200_000


def derivar(clave: str, sal: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=sal, iterations=ITERACIONES
    ).derive(clave.encode("utf-8"))


def main() -> None:
    if not ORIGEN.exists():
        sys.exit(f"No encuentro {ORIGEN}")

    clave = os.environ.get("CLAVE_NOTA") or getpass.getpass("Clave: ")
    if not clave:
        sys.exit("Clave vacia")

    html = ORIGEN.read_text(encoding="utf-8")

    # se cifra solo el cuerpo, no el documento entero
    cuerpo = re.search(r"<body[^>]*>(.*)</body>", html, re.S)
    estilos = re.search(r"<style>(.*?)</style>", html, re.S)
    if not cuerpo or not estilos:
        sys.exit("No pude aislar <body> o <style> del origen")

    carga = json.dumps(
        {"css": estilos.group(1), "html": cuerpo.group(1)}, ensure_ascii=False
    ).encode("utf-8")
    carga = gzip.compress(carga, 9)

    sal = os.urandom(16)
    iv = os.urandom(12)
    cifrado = AESGCM(derivar(clave, sal)).encrypt(iv, carga, None)
    blob = base64.b64encode(sal + iv + cifrado).decode("ascii")

    DESTINO.write_text(CASCARA.replace("__BLOB__", blob), encoding="utf-8")

    print(f"  origen : {len(html):,} bytes en claro")
    print(f"  salida : {DESTINO.name}, {DESTINO.stat().st_size:,} bytes cifrados")
    print(f"  cifrado: AES-256-GCM · PBKDF2-SHA256 · {ITERACIONES:,} iteraciones")
    print("\n  Listo. Ahora corre:  publica")


CASCARA = r"""<!DOCTYPE html>
<html lang="es-CL">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>Amplifica · Documento protegido</title>
<style>
:root{--ink:#14171a;--ink-2:#4a545e;--ink-3:#7c8894;--bg:#fbfaf7;--card:#fff;--line:#e6e2da;--acc:#0f6b5c;--warn:#a8412a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:400 17px/1.62 ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
letter-spacing:-.011em;-webkit-font-smoothing:antialiased}
#puerta{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.caja{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:30px 26px;max-width:400px;width:100%;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.caja .kick{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--acc);font-weight:650;margin:0 0 12px}
.caja h1{font-size:23px;line-height:1.25;letter-spacing:-.024em;font-weight:670;margin:0 0 8px}
.caja p{color:var(--ink-2);font-size:15.5px;margin:0 0 20px}
label{display:block;font-size:12px;letter-spacing:.07em;text-transform:uppercase;
color:var(--ink-3);font-weight:650;margin:0 0 7px}
input{width:100%;padding:13px 14px;font-size:17px;border:1px solid var(--line);
border-radius:10px;background:#fbfaf7;color:var(--ink);font-family:inherit}
input:focus{outline:none;border-color:var(--acc);background:#fff}
button{width:100%;margin-top:12px;padding:13px;font-size:16px;font-weight:600;font-family:inherit;
color:#fff;background:var(--acc);border:0;border-radius:10px;cursor:pointer}
button:disabled{opacity:.55;cursor:default}
#msg{margin:14px 0 0;font-size:14.5px;color:var(--warn);min-height:20px}
#listo{display:none}
</style>
</head>
<body>

<div id="puerta">
  <form class="caja" id="form">
    <p class="kick">Amplifica · Nota de directorio</p>
    <h1>Quién nos podría comprar algún día</h1>
    <p>Documento interno. Pide la clave a Fabián.</p>
    <label for="c">Clave</label>
    <input type="password" id="c" autocomplete="current-password" autofocus>
    <button type="submit" id="b">Abrir</button>
    <p id="msg"></p>
  </form>
</div>

<div id="listo"></div>

<script>
const BLOB = "__BLOB__";
const ITER = 200000;

const $ = id => document.getElementById(id);
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function abrir(clave){
  const raw = b64(BLOB);
  const sal = raw.slice(0,16), iv = raw.slice(16,28), datos = raw.slice(28);
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(clave), "PBKDF2", false, ["deriveKey"]);
  const llave = await crypto.subtle.deriveKey(
    { name:"PBKDF2", salt:sal, iterations:ITER, hash:"SHA-256" },
    base, { name:"AES-GCM", length:256 }, false, ["decrypt"]);
  const plano = await crypto.subtle.decrypt({ name:"AES-GCM", iv:iv }, llave, datos);

  // viene comprimido con gzip
  const ds = new DecompressionStream("gzip");
  const texto = await new Response(new Blob([plano]).stream().pipeThrough(ds)).text();
  return JSON.parse(texto);
}

$("form").addEventListener("submit", async e => {
  e.preventDefault();
  const msg = $("msg"), btn = $("b");
  msg.style.color = "var(--ink-3)";
  msg.textContent = "Abriendo…";
  btn.disabled = true;
  try {
    const doc = await abrir($("c").value);
    const est = document.createElement("style");
    est.textContent = doc.css;
    document.head.appendChild(est);
    $("puerta").remove();
    const cont = $("listo");
    cont.innerHTML = doc.html;
    cont.style.display = "block";
    document.title = "Amplifica · Quién nos podría comprar";
    cont.querySelectorAll("script").forEach(v => {
      const n = document.createElement("script");
      n.textContent = v.textContent;
      document.body.appendChild(n);
      v.remove();
    });
  } catch (err) {
    msg.style.color = "var(--warn)";
    msg.textContent = "Clave incorrecta";
    btn.disabled = false;
    $("c").select();
  }
});
</script>

</body>
</html>
"""

if __name__ == "__main__":
    main()
