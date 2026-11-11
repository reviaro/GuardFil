# The release workflow must provide a digest-pinned, trusted Go 1.27.1 builder image.
ARG GO_BUILDER_IMAGE=golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
FROM ${GO_BUILDER_IMAGE} AS build
ARG GO_BUILDER_IMAGE
WORKDIR /src
COPY go.mod ./
RUN test -n "$GO_BUILDER_IMAGE" && case "$GO_BUILDER_IMAGE" in *@sha256:*) ;; *) exit 64;; esac && test "$(go version | awk '{print $3}')" = go1.27.1
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=true -ldflags='-s -w' -o /out/guardfil ./cmd/guardfil
# The MCP filter proxy runs inside agent containers; guardfil-local.sh copies it out.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=true -ldflags='-s -w' -o /out/guardfil-mcp-proxy ./cmd/guardfil-mcp-proxy
# The model brokers (host side) and the relay (in each executor's networkless anchor).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=true -ldflags='-s -w' -o /out/guardfil-broker ./cmd/guardfil-broker
# Host-side filesystem mediation. Only its FUSE view reaches the agent.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=true -ldflags='-s -w' -o /out/guardfil-workspace ./cmd/guardfil-workspace

FROM scratch
COPY --from=build /out/guardfil /guardfil
COPY --from=build /out/guardfil-mcp-proxy /guardfil-mcp-proxy
COPY --from=build /out/guardfil-broker /guardfil-broker
COPY --from=build /out/guardfil-workspace /guardfil-workspace
USER 65532:65532
VOLUME ["/var/lib/guardfil"]
EXPOSE 8080 9090
ENTRYPOINT ["/guardfil"]
CMD ["-config", "/etc/guardfil/guardfil.yaml"]
