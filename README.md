# iphone_capture

iPhoneのSafariだけで、iPhoneのカメラをWindows PCの「Webカメラ」として使うためのツールです。iPhoneにアプリは入れません。

- 静止画の転送（高解像度撮影・カメラロールから送信）
- リアルタイム映像（WebRTC、1080p/30fps目安、4K選択可）
- OBSの「ブラウザ」ソース → 仮想カメラで Zoom / Teams などから使用

## 必要なもの
- Windows PC ＋ Python 3.8以上
- iPhone（Safari）。PCと同じLAN（Wi-Fi）か、USBのインターネット共有で接続
- 他アプリのカメラにする場合は OBS Studio

## 使い方
1. `start.bat` をダブルクリック → ブラウザに受信ページとQRが2つ出る
2. **初回のみ**: QR「1. 証明書」をiPhoneで読み、プロファイルをインストール
   - 設定 → 一般 → VPNとデバイス管理 でインストール
   - 設定 → 一般 → 情報 → 証明書信頼設定 で「iPhone Capture Local CA」をオン
3. **毎回**: QR「2. 撮影ページ」を読み、「カメラを開始」
4. 確認: 受信ページのリンク `http://127.0.0.1:8765/cam?stats=1`

### OBSで使う
1. ソース「＋」→「ブラウザ」
2. URL `http://127.0.0.1:8765/cam`、幅1920・高さ1080、カスタムフレームレート30
3. 「表示されていないときにソースをシャットダウン」はオフ
4. 他アプリで使うときは「仮想カメラ開始」→ カメラに「OBS Virtual Camera」を選択

受信ページ（`/cam`）は同時に1か所だけ開いてください。

### 有線（USB）で使う
iPhoneをUSB接続し、インターネット共有をオンにしてから `start.bat` を起動します（172.20.10.x のアドレスが優先されます）。iTunes または Appleデバイスアプリが必要です。インターネット共有が使えない契約・SIMなしの端末では使えません。

## 仕組み
- iPhoneのSafariはHTTPSでないとカメラを使えないため、ローカルCAを自動生成して `certs/` に保存し、iPhoneに信頼させます（QR 1）。
- ローカルCAには Name Constraints を付けており、LAN内のIP（10/8・172.16/12・192.168/16・100.64/10・127/8）と localhost 以外の証明書は発行できません。旧版の証明書は起動時に自動で作り直されるので、iPhoneでQR 1から入れ直してください。
- 映像は `getUserMedia` → WebRTC（H.264優先、上限 5/10/25Mbps）。SDPの受け渡しは同じPythonサーバーが行います（STUNなし＝LAN内専用）。
- URLのキーは起動ごとに変わります。`/cam` はPC自身（127.0.0.1）からのみキー不要。

## うまくいかないとき
- 「キーが一致しません」と出る → 古いタブのURLか、前回のサーバーが残っている。黒い画面を閉じて `start.bat` を再実行
- iPhoneから届かない → WindowsファイアウォールでPython（とOBS）のプライベートネットワークを許可
- iPhoneを縦に持つと縦長映像。16:9にするなら横向き

## ファイル
| ファイル | 内容 |
|---|---|
| `capture_server.py` | サーバー本体（標準ライブラリ＋`cryptography`） |
| `start.bat` / `open_page.bat` | 起動とブラウザ表示 |
| `qrcode.js` | QR Code Generator for JavaScript（Kazuhiko Arase, MIT License） |

`certs/`（秘密鍵を含む）と `captures/`（撮影画像）はリポジトリに含めません。
