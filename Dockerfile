FROM golang:1.21-alpine3.18

WORKDIR /app
COPY ./go.* ./

RUN go mod download
COPY . .

COPY start.sh .
COPY wait-for.sh .
COPY ./db/migration ./db/migration

RUN go build -o /app/server
EXPOSE 8000
# CMD [ "./server" ]
ENTRYPOINT ["/app/start.sh"]