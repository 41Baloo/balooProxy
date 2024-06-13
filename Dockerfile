FROM golang:1.19-alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

EXPOSE 80 443

CMD ["./main"]
#CMD ["/bin/sh", "-c", "./main & exec sh"]
