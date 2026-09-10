# ==============================================================================
# ÉTAPE 1 : Compilation Statique & Tests (Build Stage)
# ==============================================================================
ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-alpine AS builder

# Installation des certificats SSL/TLS racine et outils de build
RUN apk add --no-cache ca-certificates git

WORKDIR /src

# Téléchargement et vérification des dépendances Go
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Création des entrées utilisateur/groupe non-privilégiés (UID/GID 10001)
RUN echo "appgroup:x:10001:" > /tmp/group && \
    echo "appuser:x:10001:10001:AppUser:/:/sbin/nologin" > /tmp/passwd

# Copie du code source complet
COPY . .

# Exécution des tests unitaires pendant le build
RUN CGO_ENABLED=0 go test -v ./...

# La version réelle est injectée par « make docker-build », qui la lit dans le
# fichier VERSION. Le repli « dev » désigne honnêtement une image construite à la
# main : mieux vaut cela qu'un numéro figé qui mentirait sur son contenu.
ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETARCH

# Compilation statique sans dépendance dynamique (Static ELF)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -tags production \
    -trimpath \
    -ldflags="-s -w -extldflags '-static' \
      -X main.version=${BUILD_VERSION} \
      -X main.commit=${BUILD_COMMIT} \
      -X main.buildDate=${BUILD_DATE}" \
    -o /bin/sse-gateway \
    ./cmd/server

# ==============================================================================
# ÉTAPE 2 : Image minimale finale "Scratch" (zéro binaire système tiers)
# ==============================================================================
FROM scratch

# Redéclaration nécessaire : un ARG ne franchit pas la frontière d'étape.
ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

# Métadonnées OCI (annotation keys standard). Le champ « Source Repository » de
# Docker Hub n'est alimenté que par ses builds automatisés ; le rattachement de
# l'image à son code repose donc sur ces libellés, que lisent Docker Scout,
# Renovate et Dependabot indépendamment du registre.
LABEL org.opencontainers.image.title="sse-gateway"
LABEL org.opencontainers.image.description="Server-Sent Events gateway in Go: sharded hub, conditional decryption, single-serialization fan-out"
LABEL org.opencontainers.image.url="https://github.com/fdecourt/sse_gateway"
LABEL org.opencontainers.image.source="https://github.com/fdecourt/sse_gateway"
LABEL org.opencontainers.image.documentation="https://github.com/fdecourt/sse_gateway#readme"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="fdecourt"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

# Certificats SSL/TLS racine pour les connexions HTTPS/TLS sortantes (Valkey TLS, Crypto HTTP TLS, JWKS)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Configuration utilisateur non-privilégié (UID/GID 10001)
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group

# Copie du binaire statique unique
COPY --from=builder /bin/sse-gateway /usr/local/bin/sse-gateway

# Basculement vers l'utilisateur non-privilégié
USER 10001:10001

# Variables d'environnement par défaut
ENV SSE_ENVIRONMENT=production \
    SSE_HTTP_LISTEN_PORT=8080

# Exposition du port réseau interne
EXPOSE 8080

# Sonde de santé Docker autonome exécutée par le binaire Go (sans shell, curl ni wget)
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/usr/local/bin/sse-gateway", "-healthcheck"]

# Point d'entrée
ENTRYPOINT ["/usr/local/bin/sse-gateway"]
