# b61decoder-linux　(Rust Linux Alpha Version)

このプログラムは、ARIB STD-B61 および ARIB STD-B60 規格に基づいた暗号化された MMTS ファイルを復号化するツールです。

**注意:**
*   このプログラムはC#で構築されたb61decoderを解析し作成されています。
*   このプログラムは、ARIB STD-B61 および ARIB STD-B60 規格に基づいた暗号化された MMTS ファイルの復号化を試みるための実験的なものです。
*   テストはほとんど行われておらず、アルファ版です。
*   ビルド済みの実行ファイルは提供していません。
*   自己責任において使用し、セキュリティに関しては十分に注意してください。

## ビルドに必要なライブラリ

このプログラムをビルドするには、以下のライブラリが必要です。

*   **Rust toolchain:** Rust の開発環境 (rustc, Cargo)
*   **libpcsclite-dev:** PCSC (スマートカード) 通信ライブラリ
*   **pcsc-tools:** スマートカードリーダーの確認ツール
*   **openssl-devel:** 暗号化処理 (SHA256など) に使用するライブラリ

### インストール方法 (Ubuntu/Debian の場合):

```bash
sudo apt update
sudo apt install rustc cargo libpcsclite-dev pcsc-tools openssl-dev
```

*   その他ディストリビューションの場合:
*   各ディストリビューションのパッケージ管理システムで、上記のライブラリをインストールしてください。

ビルド方法
