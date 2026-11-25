# QUIC PaaS Test

PaaS の外側にあるクライアントから、コンテナ内の C++ サーバーまで UDP が届き、
アプリ自身が QUIC を終端できるかを検証します。Microsoft の
[MsQuic 公式サンプル](https://github.com/microsoft/msquic/blob/v2.6.4/src/tools/sample/sample.c)
と同じ API とコールバック構成を使います。

- 待ち受けは IPv4 の `0.0.0.0:4433/udp`、ALPN は `quic-test`。
- 双方向ストリーム上のバイト列を順序どおり返し、クライアントの FIN に続いてサーバーも FIN を返します。1 ストリームあたりの上限は 4 MiB です。
- サーバーはリスナー起動、接続受付、ハンドシェイク完了、ストリーム、送受信バイト数、切断を別々に記録します。同じ接続のログは `conn=` で追えます。
- Docker イメージは Debian slim ベースです。実行時レイヤーにはコンパイラーや SDK を含めず、UID/GID `65532:65532` で動作します。ビルド対象は Linux amd64 と arm64 です。

## GHCR のサーバーイメージ

`main` への push で GitHub Actions がサーバーイメージをビルドし、GHCR に登録します。
`linux/amd64` と `linux/arm64` に対応し、`latest` と `sha-<コミットの完全な SHA>` のタグが付きます。

```sh
docker pull ghcr.io/ikura-hamu/quic-test:latest
```

パッケージが非公開の場合は、PaaS に GHCR の読み取り資格情報を設定します。サーバー証明書と秘密鍵は起動時に環境変数で渡します。

## ローカルで起動

Docker と OpenSSL を用意し、リポジトリのルートで実行します。クライアント用イメージは別ターゲットです。

```sh
docker build -t quic-test:server .
docker build --target client -t quic-test:client .
./certs/generate.sh localhost
```

HTTPS プロキシのルート CA が必要な環境では、Docker のビルドオプションに `--secret id=build_ca_bundle,src=/path/to/ca-bundle.pem` を追加できます。指定した CA バンドルは依存関係のダウンロード時だけ使われます。

生成される CA とサーバー証明書の有効期限は 7 日間です。生成先は `certs/local/` で、ディレクトリは所有者だけがアクセスできます。サーバーコンテナには証明書と秘密鍵の PEM を環境変数で渡します。クライアントには CA 証明書だけを渡します。

```sh
docker network create quic-test
QUIC_CERT_PEM="$(cat certs/local/server.crt)" \
QUIC_KEY_PEM="$(cat certs/local/server.key)" \
docker run --rm -d --name quic-test-server --network quic-test \
  -p 127.0.0.1:4433:4433/udp \
  -e QUIC_CERT_PEM -e QUIC_KEY_PEM \
  quic-test:server
```

Linux ではホストネットワーク上のクライアントから、公開した UDP ポートを検証できます。

```sh
docker run --rm --network host \
  --mount "type=bind,src=$PWD/certs/local/ca.crt,dst=/certs/ca.crt,readonly" \
  quic-test:client localhost --ca /certs/ca.crt
docker logs quic-test-server
```

上のクライアントコマンドに `--network host` を使えない環境では、サーバーとクライアントを同じ Docker ネットワークにつなぎ、コンテナ名に対応する検証用証明書を生成します。

```sh
./certs/generate.sh quic-test-server certs/docker
```

この場合はサーバーの起動コマンドで読み込む PEM を `certs/docker/` のものに変更します。クライアントを `--network quic-test`、接続先を `quic-test-server`、CA のマウント元を `certs/docker/ca.crt` に変更します。コンテナ間の疎通確認は Docker のホスト公開ポートを経由しません。

## PaaS で検証

1. インスタンス数を **1** に固定します。外部 UDP ポート（例 `4433`）をコンテナの UDP ポートに転送する、L4 のパススルーを設定します。PaaS の HTTP/3 終端や HTTP リバースプロキシとは別の経路を使います。
2. PaaS が割り当てた公開 DNS 名を SAN に含む証明書を用意します。検証用 CA を使う場合は `./certs/generate.sh quic.example.com certs/paas` で生成し、`ca.crt` を外部クライアントに渡します。PaaS のシークレット機能で `QUIC_CERT_PEM` と `QUIC_KEY_PEM` を実行時の環境変数として注入します。
3. 下記の UDP 専用テストを行った後、同じ公開ポートと転送設定で通常の起動に切り替えます。通常モードで `QUIC listener started` を確認し、PaaS 外部から QUIC テストを実行します。
4. 単一インスタンスの結果を記録したら複数インスタンスに増やし、同時接続と維持のテストを再実行します。PaaS のインスタンス別ログと接続 ID で分散を確認します。接続中のパケットが別のバックエンドに届くと、確立済み接続でも途切れることがあります。

| サーバー設定 | 値 |
| --- | --- |
| `QUIC_PORT` | 待ち受けポート。既定値は `4433` |
| `QUIC_CERT_PEM` | サーバー証明書の PEM 本文。中間証明書がある場合はサーバー証明書を先頭に連結 |
| `QUIC_KEY_PEM` | パスフレーズなしの秘密鍵の PEM 本文 |
| `QUIC_CERT` | ファイル指定時の証明書パス。既定値は `/certs/server.crt` |
| `QUIC_KEY` | ファイル指定時の秘密鍵パス。既定値は `/certs/server.key` |

PEM は `BEGIN` と `END` の行を含めて設定します。実際の改行と、文字列の `\n` または `\r\n` で改行を表した1行の値に対応します。PEM 用の環境変数をどちらか設定した場合は、両方が空でないことが必要です。この場合は環境変数の PEM がファイル指定より優先され、Linux のメモリ上で読み込まれます。PEM 用の変数を両方とも省略するとファイル指定を使います。

`ConfigurationLoadCredential failed (status=0x7e)` が続く場合は、PEM の前後に引用符が含まれていないか、証明書がサーバー用で秘密鍵と対になっているか、秘密鍵がパスフレーズで暗号化されていないかを確認します。

### ① UDP の到達性と戻り経路

同じ転送設定のまま、サーバーコンテナの起動引数に `--udp-probe` を指定します。証明書は不要です。ローカルで試す場合は、通常のサーバーを止めてから以下を別のターミナルで実行します。

```sh
docker run --rm -p 127.0.0.1:4433:4433/udp quic-test:server --udp-probe
```

外側から Python 3 のクライアントを実行します。

```sh
python3 tools/udp_probe.py quic.example.com --port 4433
```

- サーバーの `[PASS] UDP packet received nonce=...` は往路の到達を示します。
- クライアントの `[PASS] UDP packet received and echoed from the expected address and port` は、同じ nonce が宛先として指定した IP・ポートから返ったことを示します。
- クライアントだけが失敗する場合は、表示された nonce をサーバーログで検索します。受信記録があれば戻り経路や送信元 IP・ポートを確認し、受信記録もなければ公開設定、ファイアウォール、ロードバランサーを確認します。

このモードは小さな診断データグラムを返します。テスト後は起動引数を外して QUIC を起動します。

### ②〜⑧ QUIC の検証

以下の例は、外部端末上のネイティブクライアントを使います。Docker を使う場合は `./quic-client` の代わりに `docker run --rm --mount "type=bind,src=$PWD/ca.crt,dst=/certs/ca.crt,readonly" quic-test:client` を使い、`--ca /certs/ca.crt` を渡します。公開 CA で署名された証明書では `--ca` を省略してシステムの信頼ストアを使えます。

```sh
# ②〜④ ハンドシェイク、独自 ALPN、双方向ストリーム、hello の一致
./quic-client quic.example.com --ca ca.crt

# ⑤ 同じ接続に 15 秒ごとに Echo を送信し、600 秒後にも Echo
./quic-client quic.example.com --ca ca.crt --hold 600

# ⑤ アイドルタイムアウトを確認する場合は途中の Echo を省略
./quic-client quic.example.com --ca ca.crt --hold 600 --interval 0

# ⑥ 1 MiB のバイナリデータを送り、返ってきた全バイトを比較
./quic-client quic.example.com --ca ca.crt --bytes 1048576

# ⑦ 100 接続を同時に確立して Echo（--connections 10 から開始可能）
./quic-client quic.example.com --ca ca.crt --connections 100

# ⑧ 正常に切断してから新しい QUIC 接続を 3 ラウンド確立
./quic-client quic.example.com --ca ca.crt --repeat 3

# ALPN のネガティブテスト。非ゼロ終了を期待
./quic-client quic.example.com --ca ca.crt --alpn h3
```

サーバーとクライアントの QUIC アイドルタイムアウトは 20 分に設定し、MsQuic の KeepAlive は無効にしています。クライアントは検証失敗時に非ゼロで終了します。UDP と 10 分の維持を含む基本判定のログ例です。

```text
[PASS] UDP packet received nonce=... peer=...
[PASS] QUIC handshake completed
[PASS] Custom ALPN negotiated (quic-test)
[PASS] Bidirectional stream opened
[PASS] Echo response received (5 bytes per connection, contents matched)
[PASS] Connection maintained for 10 minutes
```

QUIC 成功時は、同じ試行でサーバー側にも `Handshake completed ALPN=quic-test` とストリームの送受信ログが出ていることを確認します。UDP プローブだけ通る場合は、1,200 バイト以上の QUIC Initial を通せるか、公開 IP とポートが変わっていないか、証明書の DNS 名とチェーン、ALPN を確認します。両端でキャプチャできる場合は `tcpdump -ni any 'udp port 4433'` で往復のアドレスとポートを比較できます。大きな Echo はネットワークとフロー制御の疎通を確認するテストで、経路 MTU を数値として測定するには別途キャプチャが必要です。

## ネイティブビルド

Linux で C++20 のコンパイラー、CMake、MsQuic のライブラリと対応ヘッダーを用意します。Dockerfile と同じ MsQuic 2.6.4 を使うと依存関係が揃います。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DMSQUIC_INCLUDE_DIR=/path/to/msquic/include \
  -DMSQUIC_LIBRARY=/path/to/libmsquic.so.2
cmake --build build --parallel
./build/quic-client --help
```

ローカルのクリーンアップは `docker stop quic-test-server` と `docker network rm quic-test` です。
