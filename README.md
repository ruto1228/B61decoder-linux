# B61decoder-linux　(Rust Linux Alpha Version)

このプログラムは、ARIB STD-B61 および ARIB STD-B60 規格に基づいた暗号化された MMTS ファイルを復号化するツールです。

**注意:**
*   このプログラムはC#で構築されたB61decoder.exeを解析し作成されています。
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

### ビルド方法
```
cd b61decoder
cargo build
```

### 使用方法

ビルドが完了したら、以下のコマンドでプログラムを実行します。
```
./target/debug/b61decoder <encryptedfile.mmts> <decryptedfile.mmts>
```

*   <encryptedfile.mmts>: 復号化する暗号化された MMTS ファイルへのパス

*   <decryptedfile.mmts>: 復号化された出力ファイルを保存するパス

### 免責事項
このソフトウェアは現状有姿で提供され、いかなる保証もありません。このソフトウェアの使用によって生じたいかなる損害についても、一切の責任を負いません。
