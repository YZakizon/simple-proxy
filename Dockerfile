# Keep this exact patch version aligned with go.mod and CI.
FROM golang:1.25.13-alpine3.23@sha256:42fc3368d1c50170a452f2bf4a1dfd292a065870c3f258d799aad4316671cb69 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY main.go ./
COPY proxy ./proxy

ARG VERSION=development
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -buildid= -X main.Version=${VERSION}" \
    -o /out/simple-proxy .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=builder --chown=nonroot:nonroot /out/simple-proxy /app/simple-proxy

USER nonroot:nonroot
ENTRYPOINT ["/app/simple-proxy"]
