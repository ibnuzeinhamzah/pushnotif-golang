ARG  BUILDER_IMAGE=golang:buster
ARG  TARGET_IMAGE=scratch

FROM ${BUILDER_IMAGE} as builder

RUN apt-get update && apt-get install git ca-certificates tzdata && update-ca-certificates
ENV TZ Asia/Jakarta
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR $GOPATH/src/mypackage/myapp/

COPY go.mod .

RUN go mod download
RUN go mod verify

COPY .env .
COPY bnpbinarisk.json .
COPY go.sum .
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o /go/bin/pushalert .

FROM ${TARGET_IMAGE}

WORKDIR /home/app

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/localtime /etc/localtime
COPY --from=builder /etc/timezone /etc/timezone
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/mypackage/myapp/.env .env
COPY --from=builder /go/src/mypackage/myapp/bnpbinarisk.json bnpbinarisk.json
COPY --from=builder /go/bin/pushalert /go/bin/pushalert

ENTRYPOINT ["/go/bin/pushalert"]