FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o server ./cmd/server

FROM alpine:latest

WORKDIR /app

# 安装 Chromium 和必要依赖（chromedp 需要）
RUN apk add --no-cache \
    ca-certificates \
    chromium \
    chromium-chromedriver \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ttf-freefont \
    font-noto-cjk

# 设置 Chromium 环境变量
ENV CHROME_BIN=/usr/bin/chromium-browser
ENV CHROME_PATH=/usr/lib/chromium/

COPY --from=builder /app/server .
COPY --from=builder /app/web ./web

COPY --from=builder /app/data ./data

RUN mkdir -p /app/debug

EXPOSE 3002

CMD ["./server"]
