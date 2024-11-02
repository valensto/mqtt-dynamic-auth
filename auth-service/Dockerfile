FROM golang:1.21-alpine AS builder
WORKDIR /app
RUN apk add --no-cache gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM gcr.io/distroless/static-debian11
WORKDIR /
COPY --from=builder /app/main /main
EXPOSE 8080
CMD ["/main"]