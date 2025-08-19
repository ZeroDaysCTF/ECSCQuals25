FROM golang:alpine AS builder
COPY . /app
WORKDIR /app
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build ./champs.go

FROM alpine:latest
COPY --from=builder /app/champs /usr/local/bin/
WORKDIR /app
COPY static/ ./static/
COPY index.tmpl .
COPY flag.txt /flag.txt
ENTRYPOINT ["champs"]
