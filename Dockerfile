# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN go generate ./cmd/guard
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go test ./...
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w -buildid=' -o /out/kata-egress-guard ./cmd/guard

FROM scratch
COPY --from=build /out/kata-egress-guard /kata-egress-guard
USER 0:0
ENTRYPOINT ["/kata-egress-guard"]
