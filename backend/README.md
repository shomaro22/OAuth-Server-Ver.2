# OAuth Server Backend

## データベース（PostgreSQL）接続

### 1. DockerでPostgreSQLを起動

```bash
# プロジェクトルートで実行
docker compose up -d postgres
```

### 2. 環境変数の設定

`.env.example` をコピーして `.env` を作成し、必要に応じて編集してください。

```bash
cp .env.example .env
```

### 3. 接続確認

```bash
cd backend
go run ./cmd/server
```

`Successfully connected to PostgreSQL` と表示されれば接続成功です。
