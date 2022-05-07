FROM golang:1.15 as builder

WORKDIR /app

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' -o certsync *.go

FROM alpine:3.15 as app

WORKDIR /app

COPY --from=builder /app/certsync /app/certsync

ENTRYPOINT [ "/app/certsync" ]
