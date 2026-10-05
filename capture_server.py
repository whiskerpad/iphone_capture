"""iPhoneのSafari映像をPCで見ながら、静止画も保存する。

PCの画面にQRが出る。iPhoneのカメラで読み、証明書を一度信頼したあと、
撮影ページを開くと映像がPCへ届く。高解像度の1枚は別ボタンで保存する。

使い方:
    start.bat
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
CAPTURES = ROOT / "captures"
CERTS = ROOT / "certs"
MAX_BYTES = 40 * 1024 * 1024
MAX_FRAME = 8 * 1024 * 1024
LOCK = threading.Lock()
SIZE_CACHE: dict[str, tuple[int, int] | None] = {}
LIVE = {"data": b"", "width": 0, "height": 0, "at": 0.0}
# WebRTC のSDP受け渡し（iPhone=送信側がoffer、PC受信ページがanswer）
RTC = {"offer_id": 0, "offer": "", "answer_id": 0, "answer": "", "want": 0}
MAX_SDP = 256 * 1024
# ローカルCAが有効になる範囲（Name Constraints）。これ以外のサイトの証明書はこのCAでは作れない
PERMITTED_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"]
PERMITTED_DNS = ["localhost"]


ADAPTERS: dict = {}
VIA = {"ip": "", "at": 0.0}
ROUTE = {"data": None, "at": 0.0}
# PC受信ページ → iPhone撮影ページへの操作。iPhoneはロングポーリングで受け取り、状態を毎秒報告する
CTRL = {"next": 0, "cmds": [], "state": None, "state_at": 0.0}
CTRL_COND = threading.Condition()
CTRL_WAIT = 8.0
CTRL_KEEP = 20
MAX_STATE = 8192


def ctrl_command(msg: object) -> dict | None:
    """PCから来た操作を検証して {action, value} にする。不正なら None。"""
    if not isinstance(msg, dict):
        return None
    action = msg.get("action")
    value = msg.get("value")
    if action in ("start", "stop", "shoot"):
        return {"action": action, "value": None}
    if action == "facing" and value in ("environment", "user"):
        return {"action": action, "value": value}
    if action == "quality" and value in ("720", "1080", "2160"):
        return {"action": action, "value": value}
    if action in ("mic", "torch") and isinstance(value, bool):
        return {"action": action, "value": value}
    if action == "zoom" and isinstance(value, (int, float)) and not isinstance(value, bool):
        if 0.1 <= float(value) <= 100:
            return {"action": action, "value": float(value)}
    return None


def classify(ip: str, label: str, desc: str) -> str:
    """usb / tether / wifi / lan / tailscale / local"""
    import ipaddress
    text = f"{label} {desc}"
    low = text.lower()
    wifi = any(k in low for k in ("wi-fi", "wifi", "wlan", "wireless")) or "ワイヤレス" in text
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "lan"
    if addr.is_loopback:
        return "local"
    if "apple mobile device" in low:
        return "usb"
    if addr in ipaddress.ip_network("172.20.10.0/28"):
        return "tether" if wifi else "usb"
    if addr in ipaddress.ip_network("100.64.0.0/10") or "tailscale" in low:
        return "tailscale"
    return "wifi" if wifi else "lan"


def adapter_info(ip: str) -> dict:
    info = ADAPTERS.get(ip)
    if info:
        return dict(info)
    return {"ip": ip, "label": "", "desc": "", "kind": classify(ip, "", "")}


def lan_ok(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in PERMITTED_NETS)


def jpeg_size(data: bytes) -> tuple[int, int] | None:
    """JPEGのSOFから幅と高さを読む。画像の展開はしない。"""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 1 < len(data):
        if data[i] != 0xFF:
            return None
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            return None
        marker = data[i]
        i += 1
        if marker in (0x01, 0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > len(data):
            return None
        seglen = int.from_bytes(data[i : i + 2], "big")
        if seglen < 2 or i + seglen > len(data):
            return None
        if marker in (0xC0, 0xC1, 0xC2, 0xC3):
            if seglen < 7:
                return None
            height = int.from_bytes(data[i + 3 : i + 5], "big")
            width = int.from_bytes(data[i + 5 : i + 7], "big")
            if width <= 0 or height <= 0:
                return None
            return width, height
        if marker == 0xDA:
            return None
        i += seglen
    return None


def check_parser() -> None:
    def segment(width: int, height: int) -> bytes:
        body = bytes([8]) + height.to_bytes(2, "big") + width.to_bytes(2, "big") + bytes([1, 0x11, 0])
        return b"\xff\xc0" + (2 + len(body)).to_bytes(2, "big") + body

    app = b"\xff\xe1" + (6).to_bytes(2, "big") + b"EXIF"
    sample = b"\xff\xd8" + app + segment(4032, 3024) + b"\xff\xd9"
    if jpeg_size(sample) != (4032, 3024):
        raise SystemExit("JPEGサイズ解析の自己検査に失敗しました。")


def local_endpoints() -> list[tuple[str, str]]:
    """(IPv4, アダプタ名) を返す。Wi-Fiを先に並べる。"""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    desc = ""

    def add(ip: str, label: str) -> None:
        ip = ip.strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            return
        if ip.startswith("127.") or ip.startswith("169.254.") or ip in seen:
            return
        seen.add(ip)
        found.append((ip, label or ip))
        if ip not in ADAPTERS:
            ADAPTERS[ip] = {"ip": ip, "label": label, "desc": desc, "kind": classify(ip, label, desc)}

    output = ""
    try:
        output = subprocess.check_output(["ipconfig", "/all"], stderr=subprocess.DEVNULL)
        output = output.decode("mbcs", errors="replace")
    except (OSError, subprocess.CalledProcessError, LookupError):
        output = ""
    adapter = ""
    for line in output.splitlines():
        if line and not line.startswith(" ") and line.endswith(":"):
            adapter = line[:-1].strip()
            desc = ""
            continue
        if re.match(r"\s+(説明|Description)[\s.]*:", line):
            desc = line.split(":", 1)[1].strip()
            continue
        if "IPv4" not in line or ":" not in line:
            continue
        raw = re.split(r"[\s(]", line.split(":")[-1].strip(), maxsplit=1)[0]
        add(raw, adapter)

    desc = ""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        add(probe.getsockname()[0], "")
        probe.close()
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0], "")
    except OSError:
        pass

    def rank(item: tuple[str, str]) -> tuple[int, int, str]:
        ip, label = item
        folded = label.lower()
        wifi = 0 if ("wi-fi" in folded or "wifi" in folded or "wlan" in folded or "ワイヤレス" in label or "wireless" in folded) else 1
        if ip.startswith("192.168."):
            band = 0
        elif ip.startswith("10."):
            band = 1
        else:
            parts = ip.split(".")
            band = 2 if parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31 else 3
        return (wifi, band, ip)

    return sorted(found, key=rank)


def megapixels(width: int, height: int) -> float:
    return round(width * height / 1_000_000, 1)


def save_jpeg(data: bytes) -> tuple[Path, tuple[int, int] | None]:
    size = jpeg_size(data)
    name = datetime.now().strftime("shot_%Y%m%d_%H%M%S_%f") + ".jpg"
    path = CAPTURES / name
    with LOCK:
        path.write_bytes(data)
        SIZE_CACHE[name] = size
    return path, size


def remember_frame(data: bytes) -> tuple[int, int] | None:
    size = jpeg_size(data)
    with LOCK:
        LIVE["data"] = data
        LIVE["width"] = size[0] if size else 0
        LIVE["height"] = size[1] if size else 0
        LIVE["at"] = time.time()
    return size


def status() -> dict:
    files = sorted(CAPTURES.glob("*.jpg"), key=lambda p: p.stat().st_mtime, reverse=True)
    record: dict = {"file": None, "count": len(files), "live": None}
    if files:
        path = files[0]
        with LOCK:
            size = SIZE_CACHE.get(path.name)
            if path.name not in SIZE_CACHE:
                size = jpeg_size(path.read_bytes())
                SIZE_CACHE[path.name] = size
        record.update({
            "file": path.name,
            "path": str(path),
            "bytes": path.stat().st_size,
        })
        if size:
            record["width"] = size[0]
            record["height"] = size[1]
            record["megapixels"] = megapixels(size[0], size[1])
    with LOCK:
        data = LIVE["data"]
        width = int(LIVE["width"])
        height = int(LIVE["height"])
        at = float(LIVE["at"])
    if data and width and height:
        record["live"] = {
            "width": width,
            "height": height,
            "bytes": len(data),
            "age": round(time.time() - at, 1),
        }
    with LOCK:
        via_ip, via_at = VIA["ip"], VIA["at"]
        route, route_at = ROUTE["data"], ROUTE["at"]
    if via_ip and time.time() - via_at < 5:
        record["via"] = adapter_info(via_ip)
    if route and time.time() - route_at < 6:
        record["route"] = route
    return record


def shot_list(limit: int) -> dict:
    """キャプチャー一覧（新しい順）。サイズはキャッシュする。"""
    files = sorted(CAPTURES.glob("*.jpg"), key=lambda p: p.stat().st_mtime, reverse=True)
    items = []
    for path in files[:limit]:
        with LOCK:
            known = path.name in SIZE_CACHE
            size = SIZE_CACHE.get(path.name)
        if not known:
            try:
                size = jpeg_size(path.read_bytes())
            except OSError:
                continue
            with LOCK:
                SIZE_CACHE[path.name] = size
        st = path.stat()
        item = {"name": path.name, "bytes": st.st_size, "mtime": int(st.st_mtime)}
        if size:
            item["width"], item["height"] = size
        items.append(item)
    return {"ok": True, "total": len(files), "items": items}


def capture_path(name: str) -> Path | None:
    """captures/ 直下の .jpg だけを許可する。"""
    if not name or name != Path(name).name or Path(name).suffix.lower() != ".jpg":
        return None
    path = (CAPTURES / name).resolve()
    if CAPTURES.resolve() not in path.parents or not path.is_file():
        return None
    return path


def open_in_paint(path: Path) -> str:
    """Windowsのペイントで開く。ペイントが無ければ既定のアプリで開く。"""
    if os.name != "nt":
        raise OSError("ペイントで開けるのはWindowsだけです")
    try:
        subprocess.Popen(["mspaint.exe", str(path)])
        return "paint"
    except OSError:
        os.startfile(str(path))  # type: ignore[attr-defined]
        return "default"


def ensure_certs(ips: list[str]) -> tuple[Path, Path]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        import ipaddress
    except ImportError as exc:
        raise SystemExit("証明書用の部品がありません。start.bat をダブルクリックしてください。") from exc

    CERTS.mkdir(parents=True, exist_ok=True)
    ca_key_path = CERTS / "ca.key"
    ca_cert_path = CERTS / "ca.crt"
    ca_der_path = CERTS / "ca.cer"
    server_key_path = CERTS / "server.key"
    chain_path = CERTS / "server-chain.pem"
    stamp_path = CERTS / "ips.txt"
    nets = [ipaddress.ip_network(n) for n in PERMITTED_NETS]

    def permitted(ip: str) -> bool:
        return any(ipaddress.ip_address(ip) in n for n in nets)

    skipped = [ip for ip in ips if not permitted(ip)]
    if skipped:
        print("証明書の対象外（LAN外）のアドレス:", ", ".join(skipped), flush=True)
    names = sorted(set([ip for ip in ips if permitted(ip)] + ["127.0.0.1"]))
    stamp = "nc1\n" + "\n".join(names)

    def ca_is_constrained() -> bool:
        try:
            cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
            cert.extensions.get_extension_for_class(x509.NameConstraints)
            return True
        except Exception:
            return False

    constrained = ca_key_path.is_file() and ca_cert_path.is_file() and ca_is_constrained()
    if constrained and chain_path.is_file() and server_key_path.is_file() and stamp_path.is_file():
        if stamp_path.read_text(encoding="ascii").strip() == stamp:
            return chain_path, server_key_path

    def new_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def write_key(path: Path, key) -> None:
        path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    now = datetime.now(timezone.utc)
    if constrained:
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    else:
        if ca_cert_path.is_file():
            print("証明書をLAN限定の新しいものに作り直しました。iPhoneでQR「1. 証明書」から入れ直してください。", flush=True)
        ca_key = new_key()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Capture Local CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(d) for d in PERMITTED_DNS] + [x509.IPAddress(n) for n in nets],
                excluded_subtrees=None,
            ), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        write_key(ca_key_path, ca_key)
        ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_der_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.DER))

    server_key = new_key()
    san = [x509.DNSName("localhost")]
    for ip in names:
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_key(server_key_path, server_key)
    server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    chain_path.write_bytes(server_pem + b"\n" + ca_pem)
    stamp_path.write_text(stamp + "\n", encoding="ascii")
    return chain_path, server_key_path


def stored_uuid(name: str) -> str:
    path = CERTS / name
    if path.is_file():
        return path.read_text(encoding="ascii").strip()
    value = str(uuid.uuid4()).upper()
    path.write_text(value + "\n", encoding="ascii")
    return value


def mobileconfig() -> bytes:
    der = (CERTS / "ca.cer").read_bytes()
    wrapped = "\n".join(textwrap.wrap(base64.standard_b64encode(der).decode("ascii"), 52))
    profile = stored_uuid("profile.uuid")
    cert_id = stored_uuid("cert.uuid")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>iPhone Capture Local CA</string>
  <key>PayloadIdentifier</key><string>local.iphone.capture.ca</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{profile}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadDisplayName</key><string>iPhone Capture Local CA</string>
      <key>PayloadIdentifier</key><string>local.iphone.capture.ca.cert</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>{cert_id}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadCertificateFileName</key><string>ca.cer</string>
      <key>PayloadContent</key>
      <data>{wrapped}</data>
    </dict>
  </array>
</dict>
</plist>
"""
    return xml.encode("utf-8")


INSTALL_PAGE = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>撮影の準備</title>
<style>
  body { margin: 0; font-family: -apple-system, "Hiragino Sans", sans-serif; background: #111; color: #f3f3f3; }
  main { padding: 24px 16px 40px; }
  h1 { font-size: 22px; margin: 0 0 12px; }
  ol { padding-left: 1.2em; line-height: 1.55; }
  a { display: block; margin-top: 14px; padding: 16px; text-align: center; text-decoration: none; border-radius: 12px; font-size: 18px; }
  a.primary { background: #f4f4f4; color: #111; }
  a.secondary { color: #ddd; border: 1px solid #555; }
</style>
</head>
<body>
<main>
  <h1>撮影の準備</h1>
  <ol>
    <li>下のボタンでプロファイルを入れる</li>
    <li>設定 → 一般 → VPNとデバイス管理 でインストール</li>
    <li>設定 → 一般 → 情報 → 証明書信頼設定 で iPhone Capture Local CA をオン</li>
    <li>このページに戻り、撮影ページを開く</li>
  </ol>
  <a class="primary" href="/ca.mobileconfig">プロファイルをインストール</a>
  <a class="secondary" id="open">撮影ページを開く</a>
</main>
<script>
document.getElementById("open").href = __CAMERA_URL__;
</script>
</body>
</html>
"""

PHONE_PAGE = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>撮影</title>
<style>
  body { margin: 0; font-family: -apple-system, "Hiragino Sans", sans-serif; background: #111; color: #f3f3f3; }
  main { padding: 16px 16px 150px; }
  h1 { font-size: 22px; margin: 0 0 8px; }
  video, img.shot { width: 100%; max-height: 52vh; background: #000; object-fit: contain; }
  #status { min-height: 1.4em; font-size: 18px; }
  .note { color: #aaa; font-size: 14px; }
  .actions { position: sticky; bottom: 0; padding: 12px 16px 20px; background: #111; }
  button, label { display: block; width: 100%; box-sizing: border-box; text-align: center; padding: 16px 12px; margin-top: 10px; border-radius: 12px; font-size: 18px; border: 0; }
  button.primary, label.primary { background: #f4f4f4; color: #111; }
  button.secondary, label.secondary { background: transparent; color: #ddd; border: 1px solid #555; }
  input { position: absolute; width: 1px; height: 1px; opacity: 0; }
  select { width: 100%; font-size: 17px; padding: 10px; margin-top: 10px; border-radius: 12px; background: #222; color: #eee; border: 1px solid #555; }
  #rtc { font-size: 15px; color: #8fd18f; min-height: 1.3em; }
</style>
</head>
<body>
<main>
  <h1>撮影</h1>
  <video id="cam" autoplay playsinline muted></video>
  <p id="status">カメラを開始すると、PCに映像が出ます。</p>
  <p id="rtc"></p>
  <p id="remote" class="note"></p>
  <p class="note">映像は動画の解像度です。細かい静止画は「高解像度で撮影」です。</p>
  <img id="shot" class="shot" alt="" hidden>
</main>
<div class="actions">
  <select id="quality">
    <option value="720">リアルタイム 720p</option>
    <option value="1080" selected>リアルタイム 1080p</option>
    <option value="2160">リアルタイム 4K（Wi-Fi/USBが速い場合）</option>
  </select>
  <button id="mic" class="secondary" type="button">マイク: オフ（押すとオン）</button>
  <button id="go" class="primary" type="button">カメラを開始</button>
  <button id="save" class="secondary" type="button">今の画角を保存</button>
  <label class="primary">高解像度で撮影
    <input id="camera" type="file" accept="image/*" capture="environment">
  </label>
  <label class="secondary">カメラロールから送る
    <input id="library" type="file" accept="image/*">
  </label>
</div>
<script>
const TOKEN = __TOKEN__;
const video = document.getElementById("cam");
const status = document.getElementById("status");
const shot = document.getElementById("shot");
const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d");
let stream = null;
let timer = 0;
let busy = false;
let facing = "environment";

function loadImage(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("この写真はSafariで開けませんでした"));
    img.src = url;
  });
}

async function toJpeg(file) {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xd8) {
    return new Blob([buf], { type: "image/jpeg" });
  }
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const c = document.createElement("canvas");
    c.width = img.naturalWidth;
    c.height = img.naturalHeight;
    c.getContext("2d").drawImage(img, 0, 0);
    const jpeg = await new Promise((resolve) => c.toBlob(resolve, "image/jpeg", 0.92));
    if (!jpeg) throw new Error("JPEGへの変換に失敗しました");
    return jpeg;
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function postJpeg(path, blob) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "image/jpeg", "X-Token": TOKEN },
    body: blob,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.ok) throw new Error(data.error || "PCが受け取りませんでした");
  return data;
}

async function startCamera() {
  status.textContent = "カメラを開始しています…";
  if (stream) stream.getTracks().forEach((track) => track.stop());
  const videoOpt = Object.assign({ facingMode: { ideal: facing }, frameRate: { ideal: 30 } }, SIZES[quality.value] || SIZES["1080"]);
  lastVideoOpt = videoOpt;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: micOn ? { echoCancellation: true, noiseSuppression: true, autoGainControl: true } : false,
      video: videoOpt,
    });
  } catch (err) {
    if (micOn) {
      // マイクだけ拒否された場合は映像のみで続ける
      micOn = false;
      updateMicButton();
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: videoOpt });
        status.textContent = "マイクを使えませんでした（設定 → Safari → マイク を確認）。映像のみ送ります。";
      } catch (err2) {
        status.textContent = "カメラを開始できません。証明書の信頼設定のあと、このページを開き直してください。";
        return;
      }
    } else {
      status.textContent = "カメラを開始できません。証明書の信頼設定のあと、このページを開き直してください。";
      return;
    }
  }
  video.srcObject = stream;
  await video.play();
  document.getElementById("go").textContent = "カメラ切替";
  if (!timer) timer = setInterval(sendFrame, 150);
  started = true;
  keepAwake();
  // 開き直したカメラにもズーム・ライトを引き継ぐ（対応していれば）
  if (desiredZoom !== 1 || desiredTorch) await applyCamera().catch(() => {});
  attachTrack().catch(() => {});
  pushState();
}

function stopCamera() {
  if (stream) stream.getTracks().forEach((track) => track.stop());
  stream = null;
  started = false;
  video.srcObject = null;
  if (timer) { clearInterval(timer); timer = 0; }
  if (pc) { pc.close(); pc = null; }
  if (wake) { wake.release().catch(() => {}); wake = null; }
  desiredTorch = false;
  document.getElementById("go").textContent = "カメラを開始";
  status.textContent = "停止しました。";
  rtcLine.textContent = "";
  pushState();
}

async function sendFrame() {
  if (busy || !video.videoWidth) return;
  // リアルタイム配信中はJPEGプレビューを1秒1枚に落として帯域をWebRTCに回す
  if (rtcLive() && Date.now() - lastJpeg < 1000) return;
  lastJpeg = Date.now();
  busy = true;
  try {
    let w = video.videoWidth;
    let h = video.videoHeight;
    if (w > 1280) {
      h = Math.round(h * 1280 / w);
      w = 1280;
    }
    canvas.width = w;
    canvas.height = h;
    ctx.drawImage(video, 0, 0, w, h);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.6));
    if (!blob) return;
    await postJpeg("/frame", blob);
    status.textContent = w + "×" + h + " をPCへ送信中";
  } catch (err) {
    status.textContent = "PCへ届いていません";
  } finally {
    busy = false;
  }
}

async function saveView() {
  if (!video.videoWidth) {
    status.textContent = "先にカメラを開始してください。";
    return;
  }
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  ctx.drawImage(video, 0, 0);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.92));
  const data = await postJpeg("/upload", blob);
  status.textContent = "保存しました " + (data.width || canvas.width) + "×" + (data.height || canvas.height);
}

async function sendFile(file) {
  status.textContent = "高解像度を送っています…";
  const jpeg = await toJpeg(file);
  const data = await postJpeg("/upload", jpeg);
  shot.hidden = false;
  shot.src = URL.createObjectURL(jpeg);
  if (data.width && data.height) {
    status.textContent = "保存しました " + data.width + "×" + data.height + "（" + data.megapixels + "MP）";
  } else {
    status.textContent = "保存しました";
  }
  const track = stream && stream.getVideoTracks()[0];
  if (!track || track.readyState !== "live") await startCamera();
}

// ---- リアルタイム映像 (WebRTC) ----
const SIZES = {
  "720": { width: { ideal: 1280 }, height: { ideal: 720 } },
  "1080": { width: { ideal: 1920 }, height: { ideal: 1080 } },
  "2160": { width: { ideal: 3840 }, height: { ideal: 2160 } },
};
const quality = document.getElementById("quality");
const rtcLine = document.getElementById("rtc");
let pc = null;
let micOn = false;
let pcHasAudio = false;
let offerId = 0;
let lastWant = -1;
let lastJpeg = 0;
let started = false;
let wake = null;
let prevBytes = 0;
let prevTs = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, body) {
  const opt = { method, headers: { "X-Token": TOKEN }, cache: "no-store" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function rtcLive() {
  return !!pc && pc.connectionState === "connected";
}

function waitIce(conn) {
  if (conn.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const t = setTimeout(resolve, 2500);
    conn.addEventListener("icegatheringstatechange", () => {
      if (conn.iceGatheringState === "complete") { clearTimeout(t); resolve(); }
    });
  });
}

function bitrateFor(w, h) {
  const px = w * h;
  if (px >= 3840 * 2160 * 0.9) return 25000000;
  if (px >= 1920 * 1080 * 0.9) return 10000000;
  return 5000000;
}

async function tuneSender(sender) {
  if (!sender || !sender.track) return;
  const st = sender.track.getSettings();
  const p = sender.getParameters();
  if (!p.encodings || !p.encodings.length) p.encodings = [{}];
  p.encodings[0].maxBitrate = bitrateFor(st.width || 1920, st.height || 1080);
  p.encodings[0].maxFramerate = 30;
  p.degradationPreference = "maintain-resolution";
  try {
    await sender.setParameters(p);
  } catch (e) {
    delete p.degradationPreference;
    try { await sender.setParameters(p); } catch (e2) {}
  }
}

async function offer() {
  const track = stream && stream.getVideoTracks()[0];
  if (!track || track.readyState !== "live") return;
  if (pc) pc.close();
  const conn = new RTCPeerConnection({ iceServers: [] });
  pc = conn;
  prevBytes = 0;
  prevTs = 0;
  const tr = conn.addTransceiver(track, { direction: "sendonly", streams: [stream] });
  const audioTrack = stream.getAudioTracks()[0];
  if (audioTrack) conn.addTransceiver(audioTrack, { direction: "sendonly", streams: [stream] });
  pcHasAudio = !!audioTrack;
  const caps = window.RTCRtpSender && RTCRtpSender.getCapabilities && RTCRtpSender.getCapabilities("video");
  if (caps && tr.setCodecPreferences) {
    const h264 = caps.codecs.filter((c) => /h264/i.test(c.mimeType));
    const rest = caps.codecs.filter((c) => !/h264/i.test(c.mimeType));
    if (h264.length) { try { tr.setCodecPreferences(h264.concat(rest)); } catch (e) {} }
  }
  conn.addEventListener("connectionstatechange", () => {
    if (conn === pc && conn.connectionState === "failed") {
      setTimeout(() => { if (conn === pc) offer().catch(() => {}); }, 1000);
    }
  });
  await conn.setLocalDescription(await conn.createOffer());
  await waitIce(conn);
  if (conn !== pc) return;
  const r = await api("POST", "/rtc/offer", { sdp: conn.localDescription.sdp });
  offerId = r.id;
  pollAnswer(conn, r.id);
}

async function pollAnswer(conn, id) {
  while (conn === pc && id === offerId && !conn.remoteDescription) {
    try {
      const r = await api("GET", "/rtc/answer?id=" + id);
      if (r.sdp && conn === pc && !conn.remoteDescription) {
        await conn.setRemoteDescription({ type: "answer", sdp: r.sdp });
        await tuneSender(videoSender(conn));
        return;
      }
    } catch (e) {}
    await sleep(400);
  }
}

function videoSender(conn) {
  const t = conn && conn.getTransceivers().find((x) => x.sender && x.receiver && x.receiver.track && x.receiver.track.kind === "video");
  return t ? t.sender : null;
}
function audioSender(conn) {
  const t = conn && conn.getTransceivers().find((x) => x.sender && x.receiver && x.receiver.track && x.receiver.track.kind === "audio");
  return t ? t.sender : null;
}

async function attachTrack() {
  const track = stream && stream.getVideoTracks()[0];
  if (!track) return;
  const audioTrack = stream.getAudioTracks()[0] || null;
  const sender = videoSender(pc);
  const usable = sender && pc.connectionState !== "failed" && pc.connectionState !== "closed";
  if (usable && pcHasAudio === !!audioTrack) {
    await sender.replaceTrack(track);
    if (audioTrack) await audioSender(pc).replaceTrack(audioTrack);
    await tuneSender(sender);
  } else {
    // マイクのオン/オフが変わったときは接続し直す
    await offer();
  }
}

function updateMicButton() {
  const b = document.getElementById("mic");
  b.textContent = micOn ? "マイク: オン（押すとオフ）" : "マイク: オフ（押すとオン）";
  b.style.borderColor = micOn ? "#e55" : "";
  b.style.color = micOn ? "#f88" : "";
}
document.getElementById("mic").addEventListener("click", () => {
  micOn = !micOn;
  updateMicButton();
  if (stream) startCamera();
});

async function watchWant() {
  // PC側の受信ページ(OBS等)が開き直されたら新しいofferを出す
  for (;;) {
    try {
      const r = await api("GET", "/rtc/want");
      if (lastWant >= 0 && r.want !== lastWant && started) await offer();
      lastWant = r.want;
    } catch (e) {}
    await sleep(1000);
  }
}


const KIND_NAMES = { usb: "USB有線", tether: "iPhoneのインターネット共有(Wi-Fi)", wifi: "Wi-Fi", lan: "有線LAN", tailscale: "Tailscale", local: "このPC" };
let netinfo = null;
async function loadNet() {
  try {
    const res = await fetch("/netinfo", { headers: { "X-Token": TOKEN }, cache: "no-store" });
    if (res.ok) netinfo = await res.json();
  } catch (e) {}
}
function pcAdapter(ip) {
  return ((netinfo && netinfo.endpoints) || []).find((e) => e.ip === ip) || null;
}
function selectedPair(rep) {
  let pair = null;
  rep.forEach((s) => { if (s.type === "transport" && s.selectedCandidatePairId) pair = rep.get(s.selectedCandidatePairId); });
  if (!pair) rep.forEach((s) => { if (s.type === "candidate-pair" && s.state === "succeeded" && (s.nominated || s.selected)) pair = s; });
  if (!pair) return null;
  const l = rep.get(pair.localCandidateId);
  const r = rep.get(pair.remoteCandidateId);
  return { local: (l && (l.address || l.ip)) || "", remote: (r && (r.address || r.ip)) || "" };
}
// pcIp: PC側のアドレス（分かれば）、iphoneIp: iPhone側のアドレス
const isIPv4 = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s || "");
function routeOf(pcIp, iphoneIp) {
  const a = isIPv4(pcIp) ? pcAdapter(pcIp) : null;
  if (a) return { kind: a.kind, label: a.desc || a.label, pc: pcIp, iphone: iphoneIp || "" };
  // PC側が分からないときは、iPhoneのアドレスと同じネットワーク(/24)のPCアダプタを探す
  if (isIPv4(iphoneIp)) {
    const pre = iphoneIp.split(".").slice(0, 3).join(".") + ".";
    const m = ((netinfo && netinfo.endpoints) || []).find((e) => e.ip.indexOf(pre) === 0);
    if (m) return { kind: m.kind, label: m.desc || m.label, pc: m.ip, iphone: iphoneIp };
    if (/^172\.20\.10\./.test(iphoneIp)) return { kind: "tether", label: "", pc: "", iphone: iphoneIp };
  }
  return { kind: "lan", label: "", pc: pcIp || "", iphone: iphoneIp || "" };
}
function routeText(r) {
  if (!r) return "";
  return (KIND_NAMES[r.kind] || r.kind) + (r.label ? "（" + r.label + "）" : "");
}
loadNet();
setInterval(loadNet, 30000);

async function showStats() {
  if (!started) return;
  if (!rtcLive()) {
    const h = routeOf(location.hostname, "");
    rtcLine.textContent = "リアルタイム: PCの受信ページ(OBS)を待っています ／ 接続: " + routeText(h);
    return;
  }
  const rep = await pc.getStats();
  let o = null;
  rep.forEach((s) => { if (s.type === "outbound-rtp" && s.kind === "video") o = s; });
  if (!o) return;
  let mbps = 0;
  if (prevTs && o.timestamp > prevTs) mbps = (o.bytesSent - prevBytes) * 8 / ((o.timestamp - prevTs) / 1000) / 1e6;
  prevBytes = o.bytesSent;
  prevTs = o.timestamp;
  let codec = "";
  if (o.codecId) { const c = rep.get(o.codecId); if (c && c.mimeType) codec = c.mimeType.replace("video/", ""); }
  const lim = o.qualityLimitationReason && o.qualityLimitationReason !== "none" ? " 制限:" + o.qualityLimitationReason : "";
  rtcLine.textContent = "リアルタイム配信中 " + (o.frameWidth || "?") + "×" + (o.frameHeight || "?") + " " +
    Math.round(o.framesPerSecond || 0) + "fps " + mbps.toFixed(1) + "Mbps " + codec + lim;
  const pr = selectedPair(rep);
  let r = routeOf(pr && pr.remote, pr && pr.local);
  if (r.kind === "lan" && !r.label) r = routeOf(location.hostname, pr && pr.local);
  rtcLine.textContent += " ／ 経路: " + routeText(r) + (pcHasAudio ? " ／ マイク送信中" : "");
  rtcLine.style.color = r.kind === "usb" ? "#6cf" : "#8fd18f";
}

async function keepAwake() {
  try {
    if ("wakeLock" in navigator && !wake) {
      wake = await navigator.wakeLock.request("screen");
      wake.addEventListener("release", () => { wake = null; });
    }
  } catch (e) {}
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible" || !started) return;
  keepAwake();
  const t = stream && stream.getVideoTracks()[0];
  if (!t || t.readyState !== "live") startCamera();
});
quality.addEventListener("change", () => { if (stream) startCamera(); });
setInterval(() => { showStats().catch(() => {}); }, 1000);
watchWant();

// ---- PC受信ページからの操作 ----
const remoteLine = document.getElementById("remote");
let lastVideoOpt = null;
let desiredZoom = 1;
let desiredTorch = false;
let lastCmdId = 0;
let lastCmdMsg = "";
const CMD_NAMES = { start: "カメラ開始", stop: "停止", facing: "カメラ切替", quality: "画質", mic: "マイク", zoom: "ズーム", torch: "ライト", shoot: "撮影" };

function liveTrack() {
  const t = stream && stream.getVideoTracks()[0];
  return t && t.readyState === "live" ? t : null;
}
function camCaps() {
  const t = liveTrack();
  try { return (t && t.getCapabilities) ? (t.getCapabilities() || {}) : {}; } catch (e) { return {}; }
}

// ズーム・ライトを反映する。applyConstraints は制約を丸ごと置き換えるので、解像度などの基本制約も付け直す。
// zoom・torch は advanced ではなく基本制約に入れる。Safari(WebKit)は advanced の制約セットを1つしか採用せず、
// [{zoom}, {torch}] と分けると torch が捨てられる。また advanced の torch:false は満たせない扱いで消灯できない
async function applyCamera() {
  const t = liveTrack();
  if (!t) throw new Error("カメラが止まっています");
  const c = camCaps();
  const opt = Object.assign({}, lastVideoOpt || {});
  let any = false;
  if (c.zoom && typeof c.zoom.max === "number") {
    desiredZoom = Math.min(c.zoom.max, Math.max(c.zoom.min, desiredZoom));
    opt.zoom = desiredZoom;
    any = true;
  }
  if (c.torch) {
    opt.torch = desiredTorch;
    any = true;
  }
  if (!any) return;
  await t.applyConstraints(opt);
}

function camState() {
  const t = liveTrack();
  const c = camCaps();
  let s = {};
  try { s = t ? t.getSettings() : {}; } catch (e) {}
  return {
    running: !!t,
    facing: facing,
    quality: quality.value,
    mic: micOn,
    zoom: (c.zoom && typeof c.zoom.max === "number") ?
      { min: c.zoom.min, max: c.zoom.max, step: c.zoom.step || 0.1, value: typeof s.zoom === "number" ? s.zoom : desiredZoom } : null,
    torch: c.torch ? { on: typeof s.torch === "boolean" ? s.torch : desiredTorch } : null,
    width: s.width || video.videoWidth || 0,
    height: s.height || video.videoHeight || 0,
    rtc: rtcLive(),
    status: status.textContent,
    cmdId: lastCmdId,
    cmdMsg: lastCmdMsg,
  };
}
let pushing = false;
async function pushState() {
  if (pushing) return;
  pushing = true;
  try { await api("POST", "/ctrl/state", camState()); } catch (e) {}
  pushing = false;
}

async function runCmd(c) {
  const v = c.value;
  switch (c.action) {
    case "start":
      if (!liveTrack()) await startCamera();
      break;
    case "stop":
      stopCamera();
      break;
    case "facing":
      if (v !== facing) {
        facing = v;
        desiredZoom = 1;
        desiredTorch = false;
        if (stream) await startCamera();
      }
      break;
    case "quality":
      if (v !== quality.value) {
        quality.value = v;
        if (stream) await startCamera();
      }
      break;
    case "mic":
      if (v !== micOn) {
        micOn = v;
        updateMicButton();
        if (stream) await startCamera();
      }
      break;
    case "zoom":
      desiredZoom = v;
      if (!liveTrack()) throw new Error("カメラが止まっています");
      if (!camCaps().zoom) throw new Error("このカメラ・iOSではズームを変えられません");
      await applyCamera();
      break;
    case "torch":
      if (!liveTrack()) throw new Error("カメラが止まっています");
      if (!camCaps().torch) throw new Error("このカメラ・iOSではライトを使えません");
      desiredTorch = v;
      await applyCamera();
      await sleep(400);
      {
        const t = liveTrack();
        const now = t && t.getSettings ? t.getSettings().torch : undefined;
        if (typeof now === "boolean" && now !== v) {
          throw new Error("iPhoneがライトを" + (v ? "点けませんでした（本体が熱い・電池残量が少ないと点きません）" : "消しませんでした"));
        }
      }
      break;
    case "shoot":
      await saveView();
      break;
  }
}

async function runCmds(list) {
  // ズーム・ライトは連続で届くので最後の1つだけ実行する
  const lastOf = {};
  list.forEach((c, i) => { if (c.action === "zoom" || c.action === "torch") lastOf[c.action] = i; });
  for (let i = 0; i < list.length; i++) {
    const c = list[i];
    if (c.action in lastOf && lastOf[c.action] !== i) continue;
    const name = CMD_NAMES[c.action] || c.action;
    try {
      await runCmd(c);
      lastCmdMsg = name + ": 完了";
      if (c.action === "start" && !liveTrack()) lastCmdMsg = name + ": 失敗（" + status.textContent + "）";
    } catch (err) {
      lastCmdMsg = name + ": 失敗（" + ((err && err.message) || err) + "）";
    }
    lastCmdId = c.id;
    remoteLine.textContent = "PCから操作 ― " + lastCmdMsg;
    await pushState();
  }
}

async function watchCmd() {
  let since = -1;
  for (;;) {
    try {
      const r = await api("GET", "/ctrl/cmd?since=" + since);
      if (since >= 0 && r.cmds && r.cmds.length) await runCmds(r.cmds);
      since = r.id;
    } catch (e) {
      await sleep(1000);
    }
  }
}
watchCmd();
setInterval(() => { if (document.visibilityState === "visible") pushState(); }, 1000);

document.getElementById("go").addEventListener("click", () => {
  if (stream) facing = facing === "environment" ? "user" : "environment";
  startCamera();
});
document.getElementById("save").addEventListener("click", () => {
  saveView().catch((err) => { status.textContent = "保存できませんでした。" + (err.message || ""); });
});
function bindFile(id) {
  const input = document.getElementById(id);
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    input.value = "";
    if (!file) return;
    try { await sendFile(file); }
    catch (err) { status.textContent = "送れませんでした。" + (err.message || ""); }
  });
}
bindFile("camera");
bindFile("library");
</script>
</body>
</html>
"""

PC_PAGE = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iPhoneから受信</title>
<style>
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html, body { height: 100%; }
  body { margin: 0; font-family: "Segoe UI", "Yu Gothic UI", sans-serif; background: #f2f2f2; color: #1a1a1a;
         display: grid; grid-template-rows: auto minmax(0, 1fr) auto; grid-template-columns: minmax(0, 1fr); height: 100vh; overflow: hidden; }
  header, #main, footer { min-width: 0; }
  button { font: inherit; font-size: 14px; padding: 6px 12px; border: 1px solid #bbb; border-radius: 6px; background: #fff; cursor: pointer; }
  button:hover:not(:disabled) { background: #eaeaea; }
  button:disabled { opacity: .45; cursor: default; }
  select { font: inherit; font-size: 14px; padding: 5px 6px; }
  a { color: #0a6ebd; }

  header { display: flex; align-items: center; gap: 14px; padding: 8px 14px; background: #fff; border-bottom: 1px solid #ddd; }
  header h1 { font-size: 17px; margin: 0; white-space: nowrap; }
  #route { font-size: 13px; font-weight: 600; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  #main { display: grid; grid-template-columns: minmax(0, 1fr) 360px; gap: 10px; padding: 10px 14px; min-height: 0; }
  #stage { position: relative; display: flex; flex-direction: column; min-height: 0; }
  #view { position: relative; flex: 1; min-height: 0; background: #111; border-radius: 6px; overflow: hidden; }
  #live { display: block; width: 100%; height: 100%; object-fit: contain; }
  #wait { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; color: #aaa; font-size: 15px; text-align: center; padding: 20px; }
  .bar { display: flex; align-items: center; gap: 10px; padding-top: 6px; font-size: 13px; flex-wrap: wrap; }
  #meta { flex: 1; min-width: 0; }

  /* 接続用QR（iPhone未接続のときだけ映像の上に出す） */
  #setup { position: absolute; inset: 0 0 34px 0; background: #fff; border-radius: 6px; padding: 14px 18px; overflow: auto; border: 1px solid #ddd; }
  #setup h2 { font-size: 16px; margin: 0 0 8px; display: flex; justify-content: space-between; align-items: center; }
  .qrs { display: flex; gap: 18px; flex-wrap: wrap; }
  .qrbox { text-align: center; }
  .qrbox svg { width: 190px; height: 190px; display: block; }
  .qrbox p { margin: 4px 0 0; font-weight: 650; font-size: 14px; }
  #setup ol { line-height: 1.5; font-size: 14px; padding-left: 20px; margin: 8px 0; }
  #setup .note { font-size: 13px; color: #555; margin: 4px 0; }

  #side { display: flex; flex-direction: column; gap: 10px; min-height: 0; overflow: auto; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 10px 12px; }
  .card h2 { font-size: 14px; margin: 0 0 6px; }
  #ctrl .row { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 6px 0; font-size: 14px; }
  #ctrl .row > span.k { width: 3.6em; font-weight: 600; font-size: 13px; }
  #ctrl button[aria-pressed="true"] { background: #1a1a1a; color: #fff; border-color: #1a1a1a; }
  #czoom { flex: 1; min-width: 100px; }
  #czoomv { font-size: 12px; color: #555; width: 100%; padding-left: 3.6em; }
  #cstate { font-weight: 600; font-size: 13px; margin: 0 0 4px; }
  #cstate.off { color: #b33; }
  #cmsg { color: #555; font-size: 12px; margin: 4px 0 0; min-height: 1.3em; }
  #shot { display: block; width: 100%; max-height: 24vh; object-fit: contain; background: #111; cursor: pointer; border-radius: 4px; }
  #saved { font-size: 12px; color: #555; margin: 4px 0 0; }

  footer { background: #fff; border-top: 1px solid #ddd; padding: 6px 14px 8px; }
  .striphead { display: flex; align-items: center; gap: 12px; font-size: 13px; margin-bottom: 6px; }
  .striphead b { white-space: nowrap; }
  #path { font-family: Consolas, monospace; font-size: 12px; color: #555; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #smsg { color: #0a6ebd; white-space: nowrap; }
  #thumbs { width: 100%; display: flex; gap: 8px; overflow-x: auto; padding-bottom: 4px; min-height: 108px; }
  .th { flex: 0 0 auto; width: 150px; border: 0; padding: 0; background: none; text-align: left; cursor: pointer; border-radius: 4px; }
  .th img { display: block; width: 150px; height: 88px; object-fit: cover; background: #ddd; border-radius: 4px; border: 2px solid transparent; }
  .th:hover img { border-color: #0a6ebd; }
  .th span { display: block; font-size: 11px; color: #555; margin-top: 2px; white-space: nowrap; }
  #thumbs .empty { color: #888; font-size: 13px; align-self: center; }

  /* 狭い画面では縦に並べてスクロール */
  @media (max-width: 860px) {
    body { display: block; height: auto; overflow: auto; }
    #main { grid-template-columns: 1fr; }
    #view { height: 56vw; flex: none; }
    #setup { position: static; margin-bottom: 8px; }
  }
</style>
</head>
<body>
<header>
  <h1>iPhoneから受信</h1>
  <span id="route"></span>
  <button id="qrtoggle" type="button">接続用QRを表示</button>
</header>

<div id="main">
  <section id="stage">
    <div id="view">
      <img id="live" alt="ライブ映像" hidden>
      <div id="wait">映像待ちです。iPhoneで撮影ページを開き「カメラを開始」を押してください。</div>
    </div>
    <div class="bar">
      <span id="meta"></span>
      <button id="keep" type="button">今の映像を保存</button>
      <span>OBS用: <a id="camlink" target="_blank" rel="noopener" title="OBSのブラウザソースには ?stats=1 なしで入れる。受信ページ(/cam)は同時に1か所だけ"></a></span>
    </div>
    <div id="setup" hidden>
      <h2>iPhoneの接続 <button id="qrclose" type="button">閉じる</button></h2>
      <div class="qrs">
        <div class="qrbox"><div id="qr-setup"></div><p>1. 証明書（初回のみ）</p></div>
        <div class="qrbox"><div id="qr-camera"></div><p>2. 撮影ページ</p></div>
      </div>
      <p class="note">QRのアドレス: <select id="addr"></select>　iPhoneと同じネットワーク（Wi-Fi・USBなど）を選ぶ</p>
      <ol>
        <li>iPhoneのカメラで「1. 証明書」を読み、プロファイルを入れる</li>
        <li>設定 → 一般 → VPNとデバイス管理 でインストール</li>
        <li>設定 → 一般 → 情報 → 証明書信頼設定 で iPhone Capture Local CA をオン</li>
        <li>「2. 撮影ページ」を読み、カメラの使用を許可する</li>
      </ol>
    </div>
  </section>

  <aside id="side">
    <section id="ctrl" class="card">
      <h2>iPhoneの操作</h2>
      <p id="cstate" class="off">iPhoneの撮影ページが開かれていません</p>
      <div class="row">
        <span class="k">カメラ</span>
        <button type="button" class="cb" id="cstart">開始</button>
        <button type="button" class="cb" id="cstop">停止</button>
        <button type="button" class="cb" id="cshoot" title="iPhoneの映像解像度のまま静止画を保存します">撮影して保存</button>
      </div>
      <div class="row">
        <span class="k">向き</span>
        <button type="button" class="cb" id="cback" aria-pressed="false">背面</button>
        <button type="button" class="cb" id="cfront" aria-pressed="false">前面</button>
        <span class="k" style="margin-left:8px">ライト</span>
        <button type="button" class="cb" id="ctorch" aria-pressed="false">オフ</button>
      </div>
      <div class="row">
        <span class="k">画質</span>
        <select class="cb" id="cquality">
          <option value="720">720p</option>
          <option value="1080">1080p</option>
          <option value="2160">4K</option>
        </select>
        <span class="k" style="margin-left:8px">マイク</span>
        <button type="button" class="cb" id="cmic" aria-pressed="false">オフ</button>
      </div>
      <div class="row">
        <span class="k">ズーム</span>
        <input type="range" class="cb" id="czoom" min="1" max="1" step="0.1" value="1">
        <button type="button" class="cb" id="czoom1">1x</button>
        <button type="button" class="cb" id="czoom2">2x</button>
        <span id="czoomv">-</span>
      </div>
      <p id="cmsg"></p>
    </section>

    <section class="card">
      <h2>前回の取得画像</h2>
      <img id="shot" alt="" title="クリックでペイントで開く" hidden>
      <p id="saved">まだありません</p>
    </section>
  </aside>
</div>

<footer>
  <div class="striphead">
    <b>キャプチャー <span id="count"></span></b>
    <span id="path"></span>
    <span id="smsg"></span>
    <button id="more" type="button" hidden>さらに表示</button>
  </div>
  <div id="thumbs"><span class="empty">まだありません</span></div>
</footer>

<script src="/qrcode.js"></script>
<script>
const DATA = __DATA__;
const $ = (id) => document.getElementById(id);
const K = "k=" + encodeURIComponent(DATA.token);

// ---- 接続用QR ----
function drawQr(id, text) {
  if (!text || typeof qrcode !== "function") return;
  const code = qrcode(0, "M");
  code.addData(text);
  code.make();
  $(id).innerHTML = code.createSvgTag(6, 2);
}
const addrSel = $("addr");
(DATA.endpoints || []).forEach((ep, i) => {
  const o = document.createElement("option");
  o.value = String(i);
  o.textContent = ep.ip + "（" + ep.label + "）";
  addrSel.appendChild(o);
});
function drawAddr() {
  const ep = (DATA.endpoints || [])[Number(addrSel.value)] || { setupUrl: DATA.setupUrl, cameraUrl: DATA.cameraUrl };
  $("qr-setup").innerHTML = "";
  $("qr-camera").innerHTML = "";
  drawQr("qr-setup", ep.setupUrl);
  drawQr("qr-camera", ep.cameraUrl);
}
addrSel.addEventListener("change", drawAddr);
drawAddr();

// QRはiPhoneがつながっていないときだけ自動で出す。ボタンで手動の表示/非表示もできる
let connected = false;
let qrManual = null;   // null=自動, true=表示, false=非表示
function updateSetup() {
  const show = qrManual === null ? !connected : qrManual;
  $("setup").hidden = !show;
  $("qrtoggle").textContent = show ? "接続用QRを隠す" : "接続用QRを表示";
}
function setConnected(on) {
  if (on && !connected) qrManual = null;   // つながったら自動で隠す
  connected = on;
  updateSetup();
}
$("qrtoggle").addEventListener("click", () => { qrManual = $("setup").hidden; updateSetup(); });
$("qrclose").addEventListener("click", () => { qrManual = false; updateSetup(); });
updateSetup();

const camlink = $("camlink");
camlink.href = DATA.camUrl + "?stats=1";
camlink.textContent = DATA.camUrl;

// ---- 映像・状態 ----
const meta = $("meta");
const live = $("live");
const shot = $("shot");
let current = "";
let liveOn = false;
let lastCount = -1;
$("path").textContent = DATA.folder;
$("path").title = DATA.folder;

function formatBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return Math.round(n / 1024) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

async function poll() {
  try {
    const res = await fetch("/latest", { headers: { "X-Token": DATA.token }, cache: "no-store" });
    const data = await res.json();
    liveOn = !!(data.live && data.live.age < 3);
    if (data.live && data.live.age < 2) {
      live.hidden = false;
      $("wait").hidden = true;
      live.src = "/live.jpg?" + K + "&t=" + Date.now();
      meta.textContent = "プレビュー " + data.live.width + "×" + data.live.height;
    } else if (data.live) {
      meta.textContent = "映像が止まっています。iPhoneの撮影ページを開いたままにしてください。";
    } else {
      meta.textContent = "";
    }
    const KN = { usb: "USB有線", tether: "iPhoneのインターネット共有(Wi-Fi)", wifi: "Wi-Fi", lan: "有線LAN", tailscale: "Tailscale", local: "このPC" };
    const fmt = (r) => r ? ((KN[r.kind] || r.kind) + ((r.desc || r.label) ? "（" + (r.desc || r.label) + "）" : "")) : "";
    const parts = [];
    if (data.route) parts.push("リアルタイム映像: " + fmt(data.route));
    if (data.via) parts.push("静止画・プレビュー: " + fmt(data.via));
    const routeEl = $("route");
    routeEl.textContent = parts.length ? ("接続 ― " + parts.join(" ／ ")) : "";
    routeEl.title = routeEl.textContent;
    routeEl.style.color = (data.route && data.route.kind === "usb") || (data.via && data.via.kind === "usb") ? "#0a6ebd" : "";
    if (data.file && data.file !== current) {
      current = data.file;
      shot.hidden = false;
      shot.src = "/shots/" + encodeURIComponent(data.file) + "?" + K;
    }
    if (data.file) {
      const dims = (data.width && data.height) ? (data.width + "×" + data.height + "（" + data.megapixels + "MP） ") : "";
      $("saved").textContent = data.file + "  " + dims + formatBytes(data.bytes || 0);
    }
    if (data.count !== lastCount) {
      lastCount = data.count;
      loadShots();
    }
  } catch (err) {
    meta.textContent = "画面の更新に失敗しました。";
  }
  setConnected(liveOn || online);
}
$("keep").addEventListener("click", async () => {
  const res = await fetch("/save-live", { method: "POST", headers: { "X-Token": DATA.token } });
  const data = await res.json().catch(() => ({}));
  meta.textContent = data.ok ? ("保存しました " + data.width + "×" + data.height) : (data.error || "保存できませんでした");
});

// ---- キャプチャー一覧（サムネイル、クリックでペイント） ----
let shotLimit = 60;
const thumbUrl = new Map();   // ファイル名 → 縮小画像のURL
const thumbQueue = [];
let thumbBusy = false;
let loadingShots = false;

async function openPaint(name) {
  $("smsg").textContent = "開いています…";
  try {
    const res = await fetch("/open", {
      method: "POST",
      headers: { "X-Token": DATA.token, "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const d = await res.json().catch(() => ({}));
    $("smsg").textContent = d.ok ? (d.how === "paint" ? "ペイントで開きました: " : "既定のアプリで開きました: ") + name : (d.error || "開けませんでした");
  } catch (e) {
    $("smsg").textContent = "開けませんでした";
  }
}
shot.addEventListener("click", () => { if (current) openPaint(current); });

// 元画像は大きい（数MB・4K以上）ので、1枚ずつ縮小してから並べる
async function makeThumb(name) {
  const res = await fetch("/shots/" + encodeURIComponent(name) + "?" + K, { cache: "force-cache" });
  if (!res.ok) throw new Error("HTTP " + res.status);
  const blob = await res.blob();
  const bmp = await createImageBitmap(blob, { resizeWidth: 300, resizeQuality: "medium" });
  const c = document.createElement("canvas");
  c.width = bmp.width;
  c.height = bmp.height;
  c.getContext("2d").drawImage(bmp, 0, 0);
  bmp.close && bmp.close();
  const small = await new Promise((r) => c.toBlob(r, "image/jpeg", 0.8));
  return URL.createObjectURL(small);
}
async function runThumbs() {
  if (thumbBusy) return;
  thumbBusy = true;
  while (thumbQueue.length) {
    const { name, img } = thumbQueue.shift();
    if (thumbUrl.has(name)) { img.src = thumbUrl.get(name); continue; }
    try {
      const url = await makeThumb(name);
      thumbUrl.set(name, url);
      img.src = url;
    } catch (e) {
      img.src = "/shots/" + encodeURIComponent(name) + "?" + K;
    }
  }
  thumbBusy = false;
}
function stamp(item) {
  const m = /^shot_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/.exec(item.name);
  const t = m ? (m[2] + "/" + m[3] + " " + m[4] + ":" + m[5] + ":" + m[6]) : item.name;
  return t + (item.width ? "  " + item.width + "×" + item.height : "");
}
async function loadShots() {
  if (loadingShots) return;
  loadingShots = true;
  try {
    const res = await fetch("/shots-list?limit=" + shotLimit, { headers: { "X-Token": DATA.token }, cache: "no-store" });
    const d = await res.json();
    const box = $("thumbs");
    $("count").textContent = "（" + d.total + "枚）";
    $("more").hidden = d.total <= d.items.length;
    if (!d.items.length) {
      box.innerHTML = '<span class="empty">まだありません</span>';
      return;
    }
    const keep = new Set(d.items.map((x) => x.name));
    for (const [name, url] of thumbUrl) {
      if (!keep.has(name)) { URL.revokeObjectURL(url); thumbUrl.delete(name); }
    }
    const old = new Map();
    box.querySelectorAll(".th").forEach((el) => old.set(el.dataset.name, el));
    box.textContent = "";
    d.items.forEach((item) => {
      let el = old.get(item.name);
      if (!el) {
        el = document.createElement("button");
        el.type = "button";
        el.className = "th";
        el.dataset.name = item.name;
        el.title = item.name + "\nクリックでペイントで開く";
        const img = document.createElement("img");
        img.alt = item.name;
        const cap = document.createElement("span");
        cap.textContent = stamp(item);
        el.append(img, cap);
        el.addEventListener("click", () => openPaint(item.name));
        if (thumbUrl.has(item.name)) img.src = thumbUrl.get(item.name);
        else thumbQueue.push({ name: item.name, img });
      }
      box.appendChild(el);
    });
    runThumbs();
  } catch (e) {
    $("smsg").textContent = "一覧を読めませんでした";
  } finally {
    loadingShots = false;
  }
}
$("more").addEventListener("click", () => { shotLimit += 60; loadShots(); });
// 縦ホイールで横スクロール
$("thumbs").addEventListener("wheel", (e) => {
  if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) { $("thumbs").scrollLeft += e.deltaY; e.preventDefault(); }
}, { passive: false });

// ---- iPhoneの操作 ----
const cstate = $("cstate");
const cmsg = $("cmsg");
let cs = null;          // iPhoneから最後に届いた状態
let online = false;
let zoomHoldUntil = 0;  // スライダー操作中は状態でつまみを動かさない
let zoomTimer = 0;
let sentId = 0;
const FACING = { environment: "背面", user: "前面" };

async function ctrl(action, value) {
  try {
    const res = await fetch("/ctrl/cmd", {
      method: "POST",
      headers: { "X-Token": DATA.token, "Content-Type": "application/json" },
      body: JSON.stringify({ action, value }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok || !d.ok) { cmsg.textContent = d.error || "送れませんでした"; return; }
    sentId = d.id;
    cmsg.textContent = d.online ? "iPhoneへ送りました…" : "送りましたが、iPhoneの撮影ページが応答していません";
  } catch (e) {
    cmsg.textContent = "送れませんでした";
  }
}

function setPressed(el, on) { el.setAttribute("aria-pressed", on ? "true" : "false"); }
function zoomText(z) { return (Math.round(z * 10) / 10) + "x"; }

function renderCtrl() {
  const s = cs;
  const run = online && s && s.running;
  document.querySelectorAll("#ctrl .cb").forEach((el) => { el.disabled = !online; });
  if (!online) {
    cstate.className = "off";
    cstate.textContent = s ? "iPhoneの撮影ページが応答していません（画面ロック・Safariが裏に回った等）" : "iPhoneの撮影ページが開かれていません";
    return;
  }
  cstate.className = "";
  cstate.textContent = run ? ("撮影中 " + (s.width && s.height ? s.width + "×" + s.height + " " : "") +
    FACING[s.facing] + (s.rtc ? " ／ リアルタイム接続中" : " ／ リアルタイム未接続（/cam を開く）")) : "停止中（向き・画質・マイクは次の開始時に反映）";
  $("cstop").disabled = !run;
  $("cshoot").disabled = !run;
  $("cstart").disabled = !!run;
  setPressed($("cback"), s.facing === "environment");
  setPressed($("cfront"), s.facing === "user");
  if (document.activeElement !== $("cquality")) $("cquality").value = s.quality;
  setPressed($("cmic"), s.mic);
  $("cmic").textContent = s.mic ? "オン" : "オフ";
  const z = run ? s.zoom : null;
  ["czoom", "czoom1", "czoom2"].forEach((id) => { $(id).disabled = !z; });
  if (z) {
    const r = $("czoom");
    r.min = z.min; r.max = z.max; r.step = z.step > 0 && z.step < 1 ? z.step : 0.1;
    $("czoom2").disabled = z.max < 2;
    if (Date.now() > zoomHoldUntil) { r.value = z.value; $("czoomv").textContent = zoomText(z.value) + "（" + zoomText(z.min) + "〜" + zoomText(z.max) + "）"; }
  } else {
    $("czoomv").textContent = run ? "このカメラ・iOSでは非対応" : "-";
  }
  const t = run ? s.torch : null;
  $("ctorch").disabled = !t;
  setPressed($("ctorch"), !!(t && t.on));
  $("ctorch").textContent = t ? (t.on ? "オン" : "オフ") : (run ? "非対応" : "オフ");
  if (s.cmdMsg && s.cmdId && s.cmdId >= sentId) cmsg.textContent = "iPhone: " + s.cmdMsg;
}

async function pollCtrl() {
  try {
    const res = await fetch("/ctrl/state", { headers: { "X-Token": DATA.token }, cache: "no-store" });
    const d = await res.json();
    cs = d.state;
    online = !!(d.state && d.age !== null && d.age < 4);
  } catch (e) {
    online = false;
  }
  renderCtrl();
}

$("cstart").addEventListener("click", () => ctrl("start"));
$("cstop").addEventListener("click", () => ctrl("stop"));
$("cshoot").addEventListener("click", () => ctrl("shoot"));
$("cback").addEventListener("click", () => ctrl("facing", "environment"));
$("cfront").addEventListener("click", () => ctrl("facing", "user"));
$("cquality").addEventListener("change", (e) => ctrl("quality", e.target.value));
$("cmic").addEventListener("click", () => ctrl("mic", !(cs && cs.mic)));
$("ctorch").addEventListener("click", () => ctrl("torch", !(cs && cs.torch && cs.torch.on)));
function sendZoom(z) {
  zoomHoldUntil = Date.now() + 1500;
  $("czoomv").textContent = zoomText(z);
  if (zoomTimer) return;
  zoomTimer = setTimeout(() => { zoomTimer = 0; ctrl("zoom", Number($("czoom").value)); }, 120);
}
$("czoom").addEventListener("input", (e) => sendZoom(Number(e.target.value)));
$("czoom1").addEventListener("click", () => { $("czoom").value = 1; sendZoom(1); });
$("czoom2").addEventListener("click", () => { $("czoom").value = 2; sendZoom(2); });

poll();
setInterval(poll, 200);
pollCtrl();
setInterval(pollCtrl, 500);
</script>
</body>
</html>
"""

CAM_PAGE = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>iPhoneカメラ</title>
<style>
  html, body { margin: 0; height: 100%; background: #000; overflow: hidden; }
  video { display: block; width: 100vw; height: 100vh; object-fit: contain; background: #000; }
  #info { position: fixed; left: 8px; top: 8px; color: #7f7; font: 14px Consolas, monospace; background: rgba(0,0,0,.6); padding: 4px 8px; white-space: pre; }
</style>
</head>
<body>
<video id="v" autoplay playsinline></video>
<div id="info" hidden></div>
<script>
const TOKEN = __TOKEN__;
const SHOW = new URLSearchParams(location.search).has("stats");
const video = document.getElementById("v");
const info = document.getElementById("info");
info.hidden = !SHOW;
let pc = null;
let lastAnswered = 0;
let prevBytes = 0;
let prevTs = 0;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, body) {
  const opt = { method, headers: { "X-Token": TOKEN }, cache: "no-store" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (res.status === 403) {
    // サーバーが再起動してトークンが変わった
    setTimeout(() => location.reload(), 2000);
    throw new Error("token");
  }
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function waitIce(conn) {
  if (conn.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const t = setTimeout(resolve, 2500);
    conn.addEventListener("icegatheringstatechange", () => {
      if (conn.iceGatheringState === "complete") { clearTimeout(t); resolve(); }
    });
  });
}

let blockedSound = false;
function playWithSound() {
  // 音声付きで再生。ブラウザの自動再生制限で止められたら無音で映像だけ出す
  video.muted = false;
  video.play().then(() => { blockedSound = false; }).catch(() => {
    blockedSound = true;
    video.muted = true;
    video.play().catch(() => {});
  });
}
document.addEventListener("click", () => { if (blockedSound) playWithSound(); });

async function answer(id, sdp) {
  if (pc) pc.close();
  const conn = new RTCPeerConnection({ iceServers: [] });
  pc = conn;
  prevBytes = 0;
  prevTs = 0;
  const remote = new MediaStream();
  conn.ontrack = (e) => {
    try { e.receiver.jitterBufferTarget = 0; } catch (_) {}
    try { e.receiver.playoutDelayHint = 0; } catch (_) {}
    remote.addTrack(e.track);
    if (video.srcObject !== remote) video.srcObject = remote;
    playWithSound();
  };
  conn.onconnectionstatechange = () => {
    if (conn === pc && conn.connectionState === "failed") api("POST", "/rtc/request").catch(() => {});
  };
  await conn.setRemoteDescription({ type: "offer", sdp });
  await conn.setLocalDescription(await conn.createAnswer());
  await waitIce(conn);
  if (conn !== pc) return;
  await api("POST", "/rtc/answer", { id, sdp: conn.localDescription.sdp });
}

async function loop() {
  for (;;) {
    try {
      const r = await api("GET", "/rtc/offer?since=" + lastAnswered);
      if (r.sdp && r.id > lastAnswered) {
        lastAnswered = r.id;
        await answer(r.id, r.sdp);
      }
    } catch (e) {}
    await sleep(400);
  }
}


const KIND_NAMES = { usb: "USB有線", tether: "iPhoneのインターネット共有(Wi-Fi)", wifi: "Wi-Fi", lan: "有線LAN", tailscale: "Tailscale", local: "このPC" };
let netinfo = null;
async function loadNet() {
  try {
    const res = await fetch("/netinfo", { headers: { "X-Token": TOKEN }, cache: "no-store" });
    if (res.ok) netinfo = await res.json();
  } catch (e) {}
}
function pcAdapter(ip) {
  return ((netinfo && netinfo.endpoints) || []).find((e) => e.ip === ip) || null;
}
function selectedPair(rep) {
  let pair = null;
  rep.forEach((s) => { if (s.type === "transport" && s.selectedCandidatePairId) pair = rep.get(s.selectedCandidatePairId); });
  if (!pair) rep.forEach((s) => { if (s.type === "candidate-pair" && s.state === "succeeded" && (s.nominated || s.selected)) pair = s; });
  if (!pair) return null;
  const l = rep.get(pair.localCandidateId);
  const r = rep.get(pair.remoteCandidateId);
  return { local: (l && (l.address || l.ip)) || "", remote: (r && (r.address || r.ip)) || "" };
}
// pcIp: PC側のアドレス（分かれば）、iphoneIp: iPhone側のアドレス
const isIPv4 = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s || "");
function routeOf(pcIp, iphoneIp) {
  const a = isIPv4(pcIp) ? pcAdapter(pcIp) : null;
  if (a) return { kind: a.kind, label: a.desc || a.label, pc: pcIp, iphone: iphoneIp || "" };
  // PC側が分からないときは、iPhoneのアドレスと同じネットワーク(/24)のPCアダプタを探す
  if (isIPv4(iphoneIp)) {
    const pre = iphoneIp.split(".").slice(0, 3).join(".") + ".";
    const m = ((netinfo && netinfo.endpoints) || []).find((e) => e.ip.indexOf(pre) === 0);
    if (m) return { kind: m.kind, label: m.desc || m.label, pc: m.ip, iphone: iphoneIp };
    if (/^172\.20\.10\./.test(iphoneIp)) return { kind: "tether", label: "", pc: "", iphone: iphoneIp };
  }
  return { kind: "lan", label: "", pc: pcIp || "", iphone: iphoneIp || "" };
}
function routeText(r) {
  if (!r) return "";
  return (KIND_NAMES[r.kind] || r.kind) + (r.label ? "（" + r.label + "）" : "");
}
loadNet();
setInterval(loadNet, 30000);

let lastRoute = null;
async function reportRoute() {
  if (!pc || pc.connectionState !== "connected") return;
  const pr = selectedPair(await pc.getStats());
  if (!pr) return;
  // /cam 側: local = PC, remote = iPhone（PCのhost候補はmDNSで隠れることがある）
  lastRoute = routeOf(pr.local, pr.remote);
  api("POST", "/rtc/route", lastRoute).catch(() => {});
}
setInterval(() => { reportRoute().catch(() => {}); }, 2000);

function audioText(rep) {
  let a = null;
  rep.forEach((s) => { if (s.type === "inbound-rtp" && s.kind === "audio") a = s; });
  if (!a) return "\n音声: なし（iPhoneのマイクがオフ）";
  const lv = typeof a.audioLevel === "number" ? " レベル " + Math.round(a.audioLevel * 100) + "%" : "";
  return "\n音声: あり" + lv + (blockedSound ? "（自動再生が止められています。画面をクリックで再生）" : "");
}

async function stats() {
  if (!SHOW) return;
  if (!pc || pc.connectionState !== "connected") {
    info.textContent = "iPhoneの撮影ページで「カメラを開始」を押してください" + (pc ? "\n状態: " + pc.connectionState : "");
    return;
  }
  const rep = await pc.getStats();
  let i = null;
  rep.forEach((s) => { if (s.type === "inbound-rtp" && s.kind === "video") i = s; });
  if (!i) return;
  let mbps = 0;
  if (prevTs && i.timestamp > prevTs) mbps = (i.bytesReceived - prevBytes) * 8 / ((i.timestamp - prevTs) / 1000) / 1e6;
  prevBytes = i.bytesReceived;
  prevTs = i.timestamp;
  let codec = "";
  if (i.codecId) { const c = rep.get(i.codecId); if (c && c.mimeType) codec = c.mimeType.replace("video/", ""); }
  let delay = "";
  if (i.jitterBufferEmittedCount) delay = " バッファ" + Math.round(i.jitterBufferDelay / i.jitterBufferEmittedCount * 1000) + "ms";
  info.textContent = (i.frameWidth || "?") + "x" + (i.frameHeight || "?") + " " + Math.round(i.framesPerSecond || 0) + "fps " +
    mbps.toFixed(1) + "Mbps " + codec + delay + "\n欠落フレーム " + (i.framesDropped || 0) + " / パケットロス " + (i.packetsLost || 0) +
    (lastRoute ? "\n経路: " + routeText(lastRoute) + " " + (lastRoute.iphone || "") : "") + audioText(rep);
}

(async () => {
  for (;;) {
    try {
      const r = await api("POST", "/rtc/request");
      lastAnswered = r.id;
      break;
    } catch (e) { await sleep(1000); }
  }
  setInterval(() => { stats().catch(() => {}); }, 1000);
  loop();
})();
</script>
</body>
</html>
"""

STALE_PAGE = """<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>iPhoneから受信</title></head>
<body>
<p><b>このURLのキーが、応答したサーバーと一致しません。</b></p>
<ul>
<li>以前に開いたタブ・履歴のURLを開いている → start.bat の黒い画面に今回表示されたURLを開く</li>
<li>前回起動したサーバー(python)が残っていて、そちらが応答している → 黒い画面をすべて閉じてから start.bat を実行し直す</li>
</ul>
</body>
</html>
"""

HELP_PAGE = """<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>iPhoneから受信</title></head>
<body><p>PCで start.bat を実行し、画面に出たQRをiPhoneのカメラで読んでください。</p></body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    token = ""
    camera_url = ""
    https_port = 8443
    page_data = "{}"

    def log_message(self, fmt: str, *args) -> None:
        return

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError, ssl.SSLError):
            return

    def parts(self) -> list[str]:
        return [unquote(p) for p in urlparse(self.path).path.split("/") if p]

    def presented_token(self) -> str:
        query = parse_qs(urlparse(self.path).query)
        if query.get("k"):
            return query["k"][0]
        header = self.headers.get("X-Token", "")
        if header:
            return header
        parts = self.parts()
        if len(parts) >= 2 and parts[0] == "k":
            return parts[1]
        return ""

    def authorized(self) -> bool:
        got = self.presented_token()
        if len(got) != len(self.token):
            return False
        return secrets.compare_digest(got, self.token)

    def send_bytes(self, code: int, body: bytes, content_type: str, disposition: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str, code: int = 200) -> None:
        self.send_bytes(code, html.encode("utf-8"), "text/html; charset=utf-8")

    def send_json(self, code: int, obj: dict) -> None:
        self.send_bytes(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def read_body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        if length == 0:
            return b""
        data = self.rfile.read(length)
        if len(data) != length:
            return None
        return data

    def do_GET(self) -> None:
        parts = self.parts()
        if parts == ["favicon.ico"]:
            self.send_response(204)
            self.end_headers()
            return
        if parts == ["qrcode.js"]:
            script = ROOT / "qrcode.js"
            if not script.is_file():
                self.send_json(404, {"ok": False, "error": "qrcode.js がありません"})
                return
            self.send_bytes(200, script.read_bytes(), "text/javascript; charset=utf-8")
            return
        if parts == ["ca.mobileconfig"]:
            try:
                body = mobileconfig()
            except OSError:
                self.send_json(500, {"ok": False, "error": "証明書がありません"})
                return
            self.send_bytes(200, body, "application/x-apple-aspen-config", 'attachment; filename="iphone-capture.mobileconfig"')
            return
        if parts == ["cam"]:
            self.send_cam()
            return
        if len(parts) == 2 and parts[0] == "rtc":
            self.rtc_get(parts[1])
            return
        if len(parts) == 2 and parts[0] == "ctrl":
            self.ctrl_get(parts[1])
            return
        if parts == ["netinfo"]:
            if not self.authorized():
                self.send_json(403, {"ok": False})
                return
            with LOCK:
                ips = list(ADAPTERS)
            self.send_json(200, {"ok": True, "endpoints": [adapter_info(ip) for ip in ips]})
            return
        if parts == ["latest"]:
            if not self.authorized():
                self.send_json(403, {"ok": False})
                return
            self.send_json(200, status())
            return
        if parts == ["shots-list"]:
            if not self.authorized():
                self.send_json(403, {"ok": False})
                return
            try:
                limit = int(parse_qs(urlparse(self.path).query).get("limit", ["60"])[0])
            except ValueError:
                limit = 60
            self.send_json(200, shot_list(max(1, min(limit, 1000))))
            return
        if parts == ["live.jpg"]:
            self.send_live()
            return
        if len(parts) == 2 and parts[0] == "shots":
            self.send_shot(parts[1])
            return
        if len(parts) == 2 and parts[0] == "k":
            self.send_page()
            return
        self.send_html(HELP_PAGE)

    def send_page(self) -> None:
        if not self.authorized():
            self.send_html(STALE_PAGE, 403)
            return
        ios = re.search(r"iPhone|iPad|iPod", self.headers.get("User-Agent", ""))
        https = isinstance(self.connection, ssl.SSLSocket)
        if ios and not https:
            host = (self.headers.get("Host", "") or "").rsplit(":", 1)[0].strip("[]")
            camera_url = f"https://{host}:{self.https_port}/k/{self.token}" if lan_ok(host) else self.camera_url
            self.send_html(INSTALL_PAGE.replace("__CAMERA_URL__", json.dumps(camera_url)))
            return
        if ios and https:
            self.send_html(PHONE_PAGE.replace("__TOKEN__", json.dumps(self.token)))
            return
        self.send_html(PC_PAGE.replace("__DATA__", self.page_data))

    def is_loopback(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def send_cam(self) -> None:
        """OBSのブラウザソース用。このPC自身からは固定URL http://127.0.0.1:8765/cam で開ける。"""
        if not (self.is_loopback() or self.authorized()):
            self.send_html(STALE_PAGE, 403)
            return
        self.send_html(CAM_PAGE.replace("__TOKEN__", json.dumps(self.token)))

    def rtc_get(self, name: str) -> None:
        if not self.authorized():
            self.send_json(403, {"ok": False})
            return
        query = parse_qs(urlparse(self.path).query)

        def num(key: str) -> int:
            try:
                return int(query.get(key, ["0"])[0])
            except ValueError:
                return 0

        with LOCK:
            snap = dict(RTC)
        if name == "offer":
            body = {"ok": True, "id": snap["offer_id"]}
            if snap["offer"] and snap["offer_id"] > num("since"):
                body["sdp"] = snap["offer"]
        elif name == "answer":
            body = {"ok": True}
            if snap["answer"] and snap["answer_id"] == num("id"):
                body["sdp"] = snap["answer"]
        elif name == "want":
            body = {"ok": True, "want": snap["want"]}
        else:
            self.send_json(404, {"ok": False})
            return
        self.send_json(200, body)

    def rtc_post(self, name: str) -> None:
        if name == "route":
            raw = self.read_body(4096)
            try:
                msg = json.loads(raw.decode("utf-8")) if raw else None
            except (UnicodeDecodeError, ValueError):
                msg = None
            if not isinstance(msg, dict):
                self.send_json(400, {"ok": False})
                return
            clean = {k: str(msg.get(k, ""))[:80] for k in ("kind", "label", "iphone", "pc")}
            with LOCK:
                ROUTE["data"] = clean
                ROUTE["at"] = time.time()
            self.send_json(200, {"ok": True})
            return
        if name == "request":
            with LOCK:
                RTC["want"] += 1
                oid = RTC["offer_id"]
            self.send_json(200, {"ok": True, "id": oid})
            return
        raw = self.read_body(MAX_SDP)
        try:
            msg = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError):
            msg = None
        if not isinstance(msg, dict) or not isinstance(msg.get("sdp"), str) or not msg["sdp"].startswith("v=0"):
            self.send_json(400, {"ok": False, "error": "SDPが読めません"})
            return
        if name == "offer":
            with LOCK:
                RTC["offer_id"] += 1
                RTC["offer"] = msg["sdp"]
                RTC["answer"] = ""
                RTC["answer_id"] = 0
                oid = RTC["offer_id"]
            self.send_json(200, {"ok": True, "id": oid})
            return
        if name == "answer":
            try:
                oid = int(msg.get("id", 0))
            except (TypeError, ValueError):
                oid = 0
            with LOCK:
                ok = oid == RTC["offer_id"]
                if ok:
                    RTC["answer"] = msg["sdp"]
                    RTC["answer_id"] = oid
            if ok:
                print("リアルタイム映像を接続しました", flush=True)
            self.send_json(200, {"ok": ok})
            return
        self.send_json(404, {"ok": False})

    def ctrl_get(self, name: str) -> None:
        if not self.authorized():
            self.send_json(403, {"ok": False})
            return
        query = parse_qs(urlparse(self.path).query)
        if name == "cmd":
            # iPhone用。since より新しい操作が来るまで最大 CTRL_WAIT 秒待つ。since<0 は現在の番号だけ返す
            try:
                since = int(query.get("since", ["-1"])[0])
            except ValueError:
                since = -1
            deadline = time.time() + CTRL_WAIT
            with CTRL_COND:
                if since >= 0:
                    while CTRL["next"] <= since:
                        left = deadline - time.time()
                        if left <= 0:
                            break
                        CTRL_COND.wait(left)
                body = {"ok": True, "id": CTRL["next"],
                        "cmds": [c for c in CTRL["cmds"] if since >= 0 and c["id"] > since]}
            self.send_json(200, body)
            return
        if name == "state":
            with CTRL_COND:
                state, at = CTRL["state"], CTRL["state_at"]
            age = round(time.time() - at, 1) if state else None
            self.send_json(200, {"ok": True, "state": state, "age": age})
            return
        self.send_json(404, {"ok": False})

    def ctrl_post(self, name: str) -> None:
        raw = self.read_body(MAX_STATE)
        try:
            msg = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError):
            msg = None
        if name == "cmd":
            cmd = ctrl_command(msg)
            if cmd is None:
                self.send_json(400, {"ok": False, "error": "操作の内容が読めません"})
                return
            with CTRL_COND:
                CTRL["next"] += 1
                cmd["id"] = CTRL["next"]
                CTRL["cmds"] = (CTRL["cmds"] + [cmd])[-CTRL_KEEP:]
                online = CTRL["state"] is not None and time.time() - CTRL["state_at"] < 4
                CTRL_COND.notify_all()
            self.send_json(200, {"ok": True, "id": cmd["id"], "online": online})
            return
        if name == "state":
            if not isinstance(msg, dict):
                self.send_json(400, {"ok": False})
                return
            with CTRL_COND:
                CTRL["state"] = msg
                CTRL["state_at"] = time.time()
            self.send_json(200, {"ok": True})
            return
        self.send_json(404, {"ok": False})

    def send_live(self) -> None:
        if not self.authorized():
            self.send_json(403, {"ok": False})
            return
        with LOCK:
            data = bytes(LIVE["data"])
        if not data:
            self.send_response(204)
            self.end_headers()
            return
        self.send_bytes(200, data, "image/jpeg")

    def send_shot(self, name: str) -> None:
        if not self.authorized():
            self.send_json(403, {"ok": False})
            return
        path = capture_path(name)
        if path is None:
            self.send_json(404, {"ok": False})
            return
        self.send_bytes(200, path.read_bytes(), "image/jpeg")

    def do_POST(self) -> None:
        parts = self.parts()
        if not self.authorized():
            self.send_json(403, {"ok": False, "error": "URLが違います"})
            return
        if len(parts) == 2 and parts[0] == "rtc":
            self.rtc_post(parts[1])
            return
        if len(parts) == 2 and parts[0] == "ctrl":
            self.ctrl_post(parts[1])
            return
        if parts == ["open"]:
            # PCの受信ページ（このPC自身）からだけ、キャプチャーをペイントで開く
            if not self.is_loopback():
                self.send_json(403, {"ok": False, "error": "このPCのブラウザからだけ使えます"})
                return
            raw = self.read_body(4096)
            try:
                msg = json.loads(raw.decode("utf-8")) if raw else None
            except (UnicodeDecodeError, ValueError):
                msg = None
            name = msg.get("name") if isinstance(msg, dict) else ""
            path = capture_path(name if isinstance(name, str) else "")
            if path is None:
                self.send_json(404, {"ok": False, "error": "ファイルがありません"})
                return
            try:
                how = open_in_paint(path)
            except OSError as exc:
                self.send_json(500, {"ok": False, "error": f"開けませんでした: {exc}"})
                return
            self.send_json(200, {"ok": True, "how": how})
            return
        if parts == ["save-live"]:
            with LOCK:
                data = bytes(LIVE["data"])
            if not data:
                self.send_json(400, {"ok": False, "error": "映像がまだありません"})
                return
            self.finish_upload(data)
            return
        limit = MAX_FRAME if parts == ["frame"] else MAX_BYTES
        data = self.read_body(limit)
        if data is None or not data or data[:2] != b"\xff\xd8":
            self.send_json(400, {"ok": False, "error": "JPEGとして読めませんでした"})
            return
        if not self.is_loopback():
            try:
                local_ip = self.connection.getsockname()[0]
            except OSError:
                local_ip = ""
            with LOCK:
                VIA["ip"] = local_ip
                VIA["at"] = time.time()
        if parts == ["frame"]:
            size = remember_frame(data)
            body = {"ok": True}
            if size:
                body["width"], body["height"] = size
            self.send_json(200, body)
            return
        if parts == ["upload"]:
            self.finish_upload(data)
            return
        self.send_json(404, {"ok": False, "error": "不明な送信です"})

    def finish_upload(self, data: bytes) -> None:
        path, size = save_jpeg(data)
        record = {"ok": True, "file": path.name, "path": str(path), "bytes": len(data)}
        if size:
            record["width"], record["height"] = size
            record["megapixels"] = megapixels(size[0], size[1])
            print(f"保存 {path.name}  {size[0]}x{size[1]}  {record['megapixels']}MP", flush=True)
        else:
            print(f"保存 {path.name}", flush=True)
        self.send_json(200, record)


def wait_until_listening(port: int) -> None:
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)


def publish_page(url: str) -> None:
    """バッチがこのファイルを見てブラウザを開く。Pythonからの起動はダブルクリックでは届かない。"""
    (ROOT / "page.url").write_text(url + "\n", encoding="ascii")
    if os.environ.get("IPHONE_CAPTURE_BAT") == "1":
        print("ブラウザを開いています。", flush=True)
        return
    if os.name == "nt":
        subprocess.Popen(["cmd.exe", "/c", "start", "", url])
    else:
        webbrowser.open(url)


class ExclusiveServer(ThreadingHTTPServer):
    """Windowsでは SO_REUSEADDR だと同じポートに二重起動でき、古いサーバーが応答してしまうため排他で開く。"""
    allow_reuse_address = os.name != "nt"

    def server_bind(self) -> None:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def port_in_use(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def open_server(port: int, context: ssl.SSLContext | None = None) -> ThreadingHTTPServer:
    busy_msg = (f"ポート {port} は既に使われています。前回起動したサーバー(python)が残っている可能性があります。\n"
                "start.bat の黒い画面をすべて閉じるか、タスクマネージャーで python.exe を終了してから、もう一度 start.bat を実行してください。")
    if port_in_use(port):
        raise SystemExit(busy_msg)
    try:
        server = ExclusiveServer(("0.0.0.0", port), Handler)
    except OSError as exc:
        raise SystemExit(f"{busy_msg}\n{exc}")
    server.daemon_threads = True
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    if sys.version_info < (3, 8):
        raise SystemExit("Python 3.8 以降が必要です。")
    check_parser()
    http_port = 8765
    https_port = 8443
    if len(sys.argv) > 1:
        try:
            http_port = int(sys.argv[1])
        except ValueError:
            raise SystemExit("ポート番号は数字で指定してください。例: py -3 capture_server.py 8766")
    if https_port == http_port:
        https_port += 1
    CAPTURES.mkdir(parents=True, exist_ok=True)
    endpoints = local_endpoints()
    ips = [ip for ip, _label in endpoints]
    chain, key = ensure_certs(ips)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(chain, key)

    token = secrets.token_hex(4)
    lan = [(ip, label) for ip, label in endpoints if lan_ok(ip)]
    primary = lan[0] if lan else ("", "")
    setup_url = f"http://{primary[0]}:{http_port}/k/{token}" if primary[0] else ""
    camera_url = f"https://{primary[0]}:{https_port}/k/{token}" if primary[0] else ""
    Handler.token = token
    Handler.camera_url = camera_url
    Handler.https_port = https_port
    Handler.page_data = json.dumps({
        "token": token,
        "folder": str(CAPTURES),
        "setupUrl": setup_url,
        "cameraUrl": camera_url,
        "label": primary[1],
        "endpoints": [{
            "ip": ip,
            "label": label,
            "setupUrl": f"http://{ip}:{http_port}/k/{token}",
            "cameraUrl": f"https://{ip}:{https_port}/k/{token}",
        } for ip, label in lan],
        "camUrl": f"http://127.0.0.1:{http_port}/cam",
    }, ensure_ascii=False).replace("<", "\\u003c")

    http_server = open_server(http_port)
    https_server = open_server(https_port, context)
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    threading.Thread(target=https_server.serve_forever, daemon=True).start()

    local_url = f"http://127.0.0.1:{http_port}/k/{token}"
    print("このPCの画面を開きます。", flush=True)
    print(local_url, flush=True)
    if setup_url:
        print("iPhoneは、画面のQRを 1、2 の順に読んでください。", flush=True)
        for ip, label in lan:
            print(f"  {label}  {ip}", flush=True)
        print(setup_url, flush=True)
        print(camera_url, flush=True)
        if len(lan) > 1:
            print("iPhoneがつながらないときは、受信ページの「QRのアドレス」でiPhoneと同じネットワークを選んでください。", flush=True)
    else:
        print("LANのIPv4が見つかりません。ipconfig のWi-Fiアドレスを確認してください。", flush=True)
    print("リアルタイム映像(OBSブラウザソース用):", f"http://127.0.0.1:{http_port}/cam", flush=True)
    print("保存先:", CAPTURES, flush=True)
    print("iPhoneから届かないときは、WindowsファイアウォールでPythonのプライベートネットワークを許可してください。", flush=True)
    print("停止は Ctrl+C", flush=True)
    wait_until_listening(http_port)
    publish_page(local_url)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n停止しました。", flush=True)
    finally:
        http_server.shutdown()
        https_server.shutdown()
        http_server.server_close()
        https_server.server_close()


if __name__ == "__main__":
    main()
