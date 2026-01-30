FROM golang:1.25.1 as builder

WORKDIR /app

COPY . .

RUN go mod download && go mod verify

#RUN go test ./...

RUN CGO_ENABLED=0 go build -o /app/cert-manager-sync cmd/cert-manager-sync/*.go

FROM scratch as app

WORKDIR /app

COPY --from=builder /app/cert-manager-sync /app/cert-manager-sync

ENTRYPOINT [ "/app/cert-manager-sync" ]
