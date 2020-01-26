FROM golang:1.13.6 AS builder
WORKDIR /xfon

# Dependency layer
ENV GOPROXY=HTTPS://proxy.golang.org
COPY go.mod go.sum /xfon/
RUN go mod download

COPY cmd cmd
COPY pkg pkg
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-ldflags=-w \
    go build -o /go/bin/xfon -ldflags=-s -v \
    github.com/odacremolbap/xfon/cmd/xfon


FROM scratch AS xfon
COPY --from=builder /go/bin/xfon /bin/xfon