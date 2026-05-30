# ---------- Build stage ----------

FROM golang:1.24-alpine AS builder

WORKDIR /app

# 依存取得をキャッシュさせる
COPY go.mod go.sum ./
RUN go mod download

# ソースコピー
COPY . .

# ビルド
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server ./cmd/server

# ---------- Runtime stage ----------

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/server .

EXPOSE 8080

CMD ["./server"]
