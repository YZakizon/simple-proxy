# Stage 1: Build the Go binary
FROM golang:1.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage caching
COPY go.mod ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o simple-proxy main.go

# Stage 2: Use distroless base image
# FROM gcr.io/distroless/base-debian12
FROM alpine:latest

# Copy the binary from the builder stage
COPY --from=builder /app/simple-proxy /app/

ENV PATH=$PATH:/app

# Set the entrypoint
ENTRYPOINT ["/app/simple-proxy"]

  