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
RUN go build -o /app/server

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/server .
COPY .env .
COPY start.sh .
COPY wait-for.sh .
COPY db/migration ./db/migration

EXPOSE 8000
CMD [ "./server" ]
ENTRYPOINT [ "/app/start.sh" ]