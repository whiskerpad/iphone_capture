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

    def add(ip: str, label: str) -> None:
        ip = ip.strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            return
        if ip.startswith("127.") or ip.startswith("169.254.") or ip in seen:
            return
        seen.add(ip)
        found.append((ip, label or ip))

    output = ""
    try:
        output = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL)
        output = output.decode("mbcs", errors="replace")
    except (OSError, subprocess.CalledProcessError, LookupError):
        output = ""
    adapter = ""
    for line in output.splitlines():
        if line and not line.startswith(" ") and line.endswith(":"):
            adapter = line[:-1].strip()
            continue
        if "IPv4" not in line or ":" not in line:
            continue
        raw = re.split(r"[\s(]", line.split(":")[-1].strip(), maxsplit=1)[0]
        add(raw, adapter)

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

    def rank(item: tuple[str, str]) -> tuple[int, int, int, str]:
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
        # iPhoneのインターネット共有（USB/Wi-Fi）は 172.20.10.x。つながっていれば最優先
        usb = 0 if ip.startswith("172.20.10.") else 1
        return (usb, wifi, band, ip)

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
    return record


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
    names = sorted(set(ips + ["127.0.0.1"]))
    stamp = "\n".join(names)
    if ca_key_path.is_file() and ca_cert_path.is_file() and chain_path.is_file() and server_key_path.is_file() and stamp_path.is_file():
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
    if ca_key_path.is_file() and ca_cert_path.is_file():
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    else:
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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
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
  <p class="note">映像は動画の解像度です。細かい静止画は「高解像度で撮影」です。</p>
  <img id="shot" class="shot" alt="" hidden>
</main>
<div class="actions">
  <select id="quality">
    <option value="720">リアルタイム 720p</option>
    <option value="1080" selected>リアルタイム 1080p</option>
    <option value="2160">リアルタイム 4K（Wi-Fi/USBが速い場合）</option>
  </select>
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
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: Object.assign({ facingMode: { ideal: facing }, frameRate: { ideal: 30 } }, SIZES[quality.value] || SIZES["1080"]),
    });
  } catch (err) {
    status.textContent = "カメラを開始できません。証明書の信頼設定のあと、このページを開き直してください。";
    return;
  }
  video.srcObject = stream;
  await video.play();
  document.getElementById("go").textContent = "カメラ切替";
  if (!timer) timer = setInterval(sendFrame, 150);
  started = true;
  keepAwake();
  attachTrack().catch(() => {});
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
        await tuneSender(conn.getSenders()[0]);
        return;
      }
    } catch (e) {}
    await sleep(400);
  }
}

async function attachTrack() {
  const track = stream && stream.getVideoTracks()[0];
  if (!track) return;
  const sender = pc && pc.getSenders()[0];
  if (sender && pc.connectionState !== "failed" && pc.connectionState !== "closed") {
    await sender.replaceTrack(track);
    await tuneSender(sender);
  } else {
    await offer();
  }
}

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

async function showStats() {
  if (!started) return;
  if (!rtcLive()) {
    rtcLine.textContent = "リアルタイム: PCの受信ページ(OBS)を待っています";
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
  body { margin: 0; font-family: "Segoe UI", "Yu Gothic UI", sans-serif; background: #f4f4f4; color: #1a1a1a; }
  main { max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; }
  h1 { font-size: 24px; margin: 0 0 8px; }
  p { line-height: 1.5; }
  #live, #shot { display: block; width: 100%; max-height: 62vh; object-fit: contain; background: #111; }
  button { font-size: 16px; padding: 10px 16px; margin: 8px 0; }
  .qrs { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 8px; }
  .qrbox { background: #fff; padding: 10px; }
  .qrbox svg { width: 220px; height: 220px; }
  .qrbox p { margin: 8px 0 0; font-weight: 650; }
  ol { line-height: 1.55; }
  #path { font-family: Consolas, monospace; font-size: 14px; word-break: break-all; }
</style>
</head>
<body>
<main>
  <h1>iPhoneから受信</h1>
  <img id="live" alt="ライブ映像" hidden>
  <p id="meta">映像待ちです。下の手順のあと、iPhoneで撮影ページを開くとここに映ります。</p>
  <button id="keep" type="button">今の映像を保存</button>
  <p>リアルタイム映像（WebRTC）: <a id="camlink" target="_blank" rel="noopener"></a><br>
  Zoom等のカメラにするには、OBSの「ブラウザ」ソースにこのURL（?stats=1なし）を入れて「仮想カメラ開始」。受信ページは同時に1か所だけ開いてください。</p>
  <div class="qrs">
    <div class="qrbox"><div id="qr-setup"></div><p>1. 証明書</p></div>
    <div class="qrbox"><div id="qr-camera"></div><p>2. 撮影ページ</p></div>
  </div>
  <p id="which"></p>
  <ol>
    <li>iPhoneのカメラで「1. 証明書」を読み、リンクを開く</li>
    <li>プロファイルを入れ、設定 → 一般 → VPNとデバイス管理 でインストール</li>
    <li>設定 → 一般 → 情報 → 証明書信頼設定 で iPhone Capture Local CA をオン</li>
    <li>「2. 撮影ページ」を読み、カメラの使用を許可する</li>
  </ol>
  <p id="saved"></p>
  <img id="shot" alt="" hidden>
  <p id="path"></p>
</main>
<script src="/qrcode.js"></script>
<script>
const DATA = __DATA__;
function drawQr(id, text) {
  if (!text || typeof qrcode !== "function") return;
  const code = qrcode(0, "M");
  code.addData(text);
  code.make();
  document.getElementById(id).innerHTML = code.createSvgTag(6, 2);
}
drawQr("qr-setup", DATA.setupUrl);
const camlink = document.getElementById("camlink");
camlink.href = DATA.camUrl + "?stats=1";
camlink.textContent = DATA.camUrl;
drawQr("qr-camera", DATA.cameraUrl);
document.getElementById("which").textContent = DATA.label ? ("QRのアドレス: " + DATA.label) : "";
const meta = document.getElementById("meta");
const saved = document.getElementById("saved");
const path = document.getElementById("path");
const live = document.getElementById("live");
const shot = document.getElementById("shot");
let current = "";
path.textContent = "保存先 " + DATA.folder;

function formatBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return Math.round(n / 1024) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

async function poll() {
  try {
    const res = await fetch("/latest", { headers: { "X-Token": DATA.token }, cache: "no-store" });
    const data = await res.json();
    if (data.live && data.live.age < 2) {
      live.hidden = false;
      live.src = "/live.jpg?k=" + encodeURIComponent(DATA.token) + "&t=" + Date.now();
      meta.textContent = data.live.width + "×" + data.live.height + " を表示中";
    } else if (data.live) {
      meta.textContent = "映像が止まっています。iPhoneの撮影ページを開いたままにしてください。";
    } else {
      meta.textContent = "映像待ちです。証明書のあと、撮影ページを開くとここに映ります。";
    }
    if (data.file && data.file !== current) {
      current = data.file;
      shot.hidden = false;
      shot.src = "/shots/" + encodeURIComponent(data.file) + "?k=" + encodeURIComponent(DATA.token);
    }
    if (data.file) {
      const dims = (data.width && data.height) ? (data.width + "×" + data.height + "（" + data.megapixels + "MP） ") : "";
      saved.textContent = "最後の静止画 " + dims + formatBytes(data.bytes || 0);
      path.textContent = data.path || DATA.folder;
    }
  } catch (err) {
    meta.textContent = "画面の更新に失敗しました。";
  }
}
document.getElementById("keep").addEventListener("click", async () => {
  const res = await fetch("/save-live", { method: "POST", headers: { "X-Token": DATA.token } });
  const data = await res.json().catch(() => ({}));
  meta.textContent = data.ok ? ("保存しました " + data.width + "×" + data.height) : (data.error || "保存できませんでした");
});
poll();
setInterval(poll, 200);
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
<video id="v" autoplay playsinline muted></video>
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

async function answer(id, sdp) {
  if (pc) pc.close();
  const conn = new RTCPeerConnection({ iceServers: [] });
  pc = conn;
  prevBytes = 0;
  prevTs = 0;
  conn.ontrack = (e) => {
    try { e.receiver.jitterBufferTarget = 0; } catch (_) {}
    try { e.receiver.playoutDelayHint = 0; } catch (_) {}
    video.srcObject = e.streams[0] || new MediaStream([e.track]);
    video.play().catch(() => {});
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
    mbps.toFixed(1) + "Mbps " + codec + delay + "\n欠落フレーム " + (i.framesDropped || 0) + " / パケットロス " + (i.packetsLost || 0);
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
        if parts == ["latest"]:
            if not self.authorized():
                self.send_json(403, {"ok": False})
                return
            self.send_json(200, status())
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
            self.send_html(INSTALL_PAGE.replace("__CAMERA_URL__", json.dumps(self.camera_url)))
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
        if name != Path(name).name or Path(name).suffix.lower() != ".jpg":
            self.send_json(404, {"ok": False})
            return
        path = (CAPTURES / name).resolve()
        if CAPTURES.resolve() not in path.parents or not path.is_file():
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
    primary = endpoints[0] if endpoints else ("", "")
    setup_url = f"http://{primary[0]}:{http_port}/k/{token}" if primary[0] else ""
    camera_url = f"https://{primary[0]}:{https_port}/k/{token}" if primary[0] else ""
    Handler.token = token
    Handler.camera_url = camera_url
    Handler.page_data = json.dumps({
        "token": token,
        "folder": str(CAPTURES),
        "setupUrl": setup_url,
        "cameraUrl": camera_url,
        "label": primary[1],
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
        print(primary[1], flush=True)
        print(setup_url, flush=True)
        print(camera_url, flush=True)
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
