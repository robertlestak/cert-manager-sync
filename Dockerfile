FROM golang:1.22.5 AS builder

WORKDIR /app

COPY . .

RUN go mod download && go mod verify

#RUN go test ./...

RUN CGO_ENABLED=0 go build -o /app/cert-manager-sync cmd/cert-manager-sync/*.go

FROM alpine:3.21 AS alpine

RUN apk add -U --no-cache ca-certificates

FROM scratch AS app

WORKDIR /app

COPY --from=builder /app/cert-manager-sync /app/cert-manager-sync
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "/app/cert-manager-sync" ]
