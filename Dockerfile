FROM golang:1.24.3 as builder

WORKDIR /app

COPY . .

RUN go mod download && go mod verify

#RUN go test ./...

RUN CGO_ENABLED=0 go build -o /app/cert-manager-sync cmd/cert-manager-sync/*.go

FROM alpine:3.21 as alpine

RUN apk add -U --no-cache ca-certificates

FROM scratch as app

WORKDIR /app

COPY --from=builder /app/cert-manager-sync /app/cert-manager-sync
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "/app/cert-manager-sync" ]
