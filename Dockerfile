# FROM golang:1.21-alpine3.18

# WORKDIR /app
# COPY ./go.* ./

# RUN go mod download
# COPY . .

# COPY start.sh .
# COPY wait-for.sh .
# COPY ./db/migration ./db/migration

# # RUN go build -o /app/server
# EXPOSE 8000
# CMD [ "go","run","main.go" ]
# # ENTRYPOINT ["/app/start.sh"]

FROM golang:1.21-alpine3.18 AS builder

WORKDIR /app
COPY ./go.* ./

RUN go mod download
COPY . .

# RUN mkdir -p /app/migrate
RUN go build -o /app/server

# Build a migration binary
# RUN go build -o /app/migrate ./migrate

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/server .
COPY .env .
COPY start.sh .
COPY wait-for.sh .
COPY db/migration ./db/migration
# RUN chmod +x migrate
# RUN ./migrate -path ./db/migration -database "postgresql://root@cockroach:26257/userstore?sslmode=disable" up

EXPOSE 8000
CMD [ "./server" ]
ENTRYPOINT [ "/app/start.sh" ]