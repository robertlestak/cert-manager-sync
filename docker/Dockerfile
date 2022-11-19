FROM golang:1.18 as builder

WORKDIR /app

COPY . .

RUN go build -o certsync *.go

FROM golang:1.18 as app

WORKDIR /app

COPY --from=builder /app/certsync /app/certsync

ENTRYPOINT [ "/app/certsync" ]
