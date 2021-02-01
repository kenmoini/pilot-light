FROM registry.access.redhat.com/ubi8/go-toolset:1.14.12
#FROM golang:1.14.3-alpine AS build

WORKDIR /src
COPY . .
RUN go build

FROM scratch AS bin

COPY --from=build /src/pilot-light /