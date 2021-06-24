FROM golang:1.15

WORKDIR /app

COPY . .

RUN go build -o certsync *.go

ENTRYPOINT [ "/app/certsync" ]