.PHONY: help build test test-race test-e2e bench run vulncheck version-check dev-keys load-test load-events \
	docker-build docker-up docker-down docker-dev docker-dev-down docker-test docker-push \
	docker-describe release clean

DOCKER_USER ?= fdecourt
IMAGE_NAME  ?= sse_gateway

# Deux dépôts Git : l'un porte l'historique réel, l'autre l'instantané publiable.
GIT_PRIVATE_REMOTE ?= origin
GIT_PUBLIC_REMOTE  ?= public

# Le fichier VERSION fait foi pour tout ce qui est construit et publié : étiquette
# d'image, estampille du binaire et libellé OCI en dérivent. Monter de version se
# résume donc à l'éditer, sans risque qu'une déclaration reste en arrière.
IMAGE_TAG   ?= $(shell cat VERSION)

# Fichiers portant une version épinglée à dessein — documentation lisible et
# déploiement déterministe — plutôt que dérivée de VERSION. Un garde-fou vérifie
# qu'aucun d'eux ne prend du retard lors d'une montée de version.
VERSION_PINNED_FILES := docker-compose.yml .env.example README.md README.fr.md

# Répertoire des identifiants de développement (graine EdDSA, fragment
# d'environnement de la passerelle, tickets pré-signés pour k6). Jamais versionné.
DEV_KEY_DIR   ?= .dev
DEV_TICKETS   ?= 200
DEV_COMPOSE   := docker compose -f docker-compose.dev.yml

# Estampilles injectées dans le binaire via -ldflags. Dérivées du dépôt afin que
# `sse-gateway -version` désigne exactement le commit à partir duquel l'image a été
# construite ; surchargeables depuis l'environnement pour une compilation hors dépôt.
BUILD_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

help:
	@echo "Commandes disponibles pour la passerelle SSE ultra-performante (Go) :"
	@echo "  make test            - Exécute les tests unitaires et d'intégration Go"
	@echo "  make test-race       - Exécute les tests avec le détecteur de race conditions (requiert CGO)"
	@echo "  make test-e2e        - Démarre la pile de dev et valide la chaîne cryptographique complète"
	@echo "  make bench           - Exécute la suite de benchmarks haute performance du Hub et fan-out"
	@echo "  make dev-keys        - Amorce les identifiants de développement dans $(DEV_KEY_DIR)/"
	@echo "  make load-test       - Charge k6 : montée en connexions SSE persistantes"
	@echo "  make load-events     - Injecte du trafic réellement chiffré dans la pile de dev"
	@echo "  make vulncheck       - Analyse les vulnérabilités de dépendances via govulncheck"
	@echo "  make version-check   - Vérifie que chaque version épinglée s'accorde au fichier VERSION"
	@echo "  make build           - Compile le binaire statique Go localement dans bin/sse-gateway"
	@echo "  make run             - Démarre la passerelle SSE en local (port 8080)"
	@echo "  make docker-build    - Construit l'image Docker durcie, estampillée du commit courant"
	@echo "  make docker-up       - Démarre la passerelle via docker compose"
	@echo "  make docker-down     - Arrête les conteneurs docker compose"
	@echo "  make docker-dev      - Démarre l'environnement complet de dev (SSE + Valkey + PQ-Crypto)"
	@echo "  make docker-dev-down - Arrête l'environnement de développement"
	@echo "  make docker-test     - Lance les tests automatisés au sein d'un conteneur Go éphémère"
	@echo "  make docker-push     - Publie l'image sur Docker Hub ($(IMAGE_TAG) et latest)"
	@echo "  make docker-describe - Pousse le README anglais en description du dépôt Docker Hub"
	@echo "  make release         - Publie tout : privé, instantané public, puis image estampillée"
	@echo "  make clean           - Supprime les artefacts de compilation"

test:
	go test -v ./...

test-race:
	go test -v -race ./...

# Les tests de bout en bout exigent une pile vivante ; ils sont donc isolés
# derrière l'étiquette « e2e » afin que `make test` reste hermétique.
# -count=1 désarme le cache : un test qui interroge un service distant ne doit
# jamais rendre un verdict mis en cache.
test-e2e: docker-dev
	go test -v -tags=e2e -count=1 ./tests/e2e

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

bench:
	go test -v -benchmem -bench=Benchmark ./tests

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sse-gateway ./cmd/server

run:
	SSE_ENVIRONMENT=development SSE_EVENT_BUS_DRIVER=memory SSE_CRYPTO_DRIVER=mock SSE_AUTH_DRIVER=mock go run ./cmd/server

# Refuse toute version divergente du fichier VERSION : une image publiée sous une
# étiquette que la documentation contredit est pire qu'une absence de publication.
version-check:
	@stray=$$(grep -hoE '[0-9]+(\.[0-9]+){2,3}' $(VERSION_PINNED_FILES) \
		| grep -vE '^[0-9]+(\.[0-9]+){3}$$' \
		| sort -u | grep -v '^$(IMAGE_TAG)$$' || true); \
	if [ -n "$$stray" ]; then \
		echo "Versions divergentes du fichier VERSION ($(IMAGE_TAG)) :"; \
		echo "$$stray"; \
		exit 1; \
	fi; \
	echo "Cohérence de version confirmée : $(IMAGE_TAG)"

# L'image publiée se construit sans passer par Compose, pour deux raisons.
# Compose lit d'office le .env du projet, qui épingle sa propre étiquette pour le
# déploiement local : l'image pourrait sortir étiquetée d'une version et
# estampillée d'une autre. Et il ajoute des libellés com.docker.compose.*, dont
# le nom du répertoire de travail, qui n'ont rien à faire dans une image publique.
docker-build: version-check
	docker build \
		--build-arg BUILD_VERSION=$(IMAGE_TAG) \
		--build-arg BUILD_COMMIT=$(BUILD_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

# Amorçage idempotent : la graine EdDSA existante est conservée, donc les
# tickets déjà distribués et la configuration de la passerelle restent valides.
dev-keys:
	go run ./tests/harness/cmd/testkeys -dir $(DEV_KEY_DIR) -tickets $(DEV_TICKETS)

# --wait bloque jusqu'à ce que les sondes de santé passent au vert : les tests
# n'ont ainsi jamais à attendre le démarrage à l'aveugle.
docker-dev: dev-keys
	$(DEV_COMPOSE) up -d --build --wait

docker-dev-down:
	$(DEV_COMPOSE) down

load-test: dev-keys
	k6 run tests/k6/sse-load.js

load-events:
	go run ./tests/harness/cmd/eventgen

docker-test:
	docker run --rm -v "$(PWD)":/app -w /app golang:alpine sh -c "CGO_ENABLED=0 go test -v ./..."

# ------------------------------------------------------------------------------
# Métadonnées du dépôt Docker Hub — purement administratif, sans rapport avec la
# version publiée.
# ------------------------------------------------------------------------------
# Le champ natif « Source Repository » du Hub n'est alimenté que par ses builds
# automatisés, réservés aux offres payantes. Le rattachement au dépôt GitHub
# repose donc sur les libellés OCI de l'image et sur cette description longue,
# qui est le README anglais poussé tel quel : un texte d'accueil propre au
# registre divergerait du dépôt au premier changement.
#
# L'identifiant est lu dans un fichier du répertoire non versionné plutôt que
# passé en argument, afin qu'il n'apparaisse ni dans l'historique du shell ni
# dans la table des processus.
HUB_REPO        ?= $(DOCKER_USER)/$(IMAGE_NAME)
HUB_SECRET_FILE ?= $(DEV_KEY_DIR)/dockerhub.secret
HUB_README      ?= README.md
HUB_SHORT_DESC  ?= Server-Sent Events gateway in Go: sharded hub, conditional decryption, static scratch image

docker-describe:
	@test -s "$(HUB_SECRET_FILE)" || { \
		echo "Aucun identifiant : déposez le mot de passe ou le jeton Docker Hub dans $(HUB_SECRET_FILE)."; \
		exit 1; }
	@token=$$(jq -n --arg u "$(DOCKER_USER)" --arg p "$$(cat "$(HUB_SECRET_FILE)")" '{username:$$u,password:$$p}' \
		| curl -sS -H "Content-Type: application/json" -d @- "https://hub.docker.com/v2/users/login/" \
		| jq -r '.token // empty'); \
	if [ -z "$$token" ]; then echo "Authentification Docker Hub refusée."; exit 1; fi; \
	code=$$(jq -n --rawfile readme "$(HUB_README)" --arg short "$(HUB_SHORT_DESC)" \
			'{full_description:$$readme, description:$$short}' \
		| curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
			-H "Content-Type: application/json" -H "Authorization: JWT $$token" \
			-d @- "https://hub.docker.com/v2/repositories/$(HUB_REPO)/"); \
	if [ "$$code" != "200" ]; then \
		echo "Mise à jour refusée (HTTP $$code). Un jeton personnel est parfois interdit sur ce point d'accès : réessayez avec le mot de passe du compte."; \
		exit 1; \
	fi; \
	echo "Description de $(HUB_REPO) mise à jour depuis $(HUB_README)."

# ------------------------------------------------------------------------------
# Publication complète
# ------------------------------------------------------------------------------
# Le dépôt public est un instantané sans historique : un commit racine unique,
# régénéré à chaque publication et amputé de $(PUBLIC_EXCLUDE). Il n'a donc
# jamais d'ancêtre commun avec le dépôt privé, d'où le push forcé.
#
# L'ordre des étapes est la raison d'être de cette cible. L'image doit être
# estampillée du commit de l'instantané public, et non du commit privé : son
# libellé org.opencontainers.image.revision désignerait sinon un sha introuvable
# à l'URL que porte org.opencontainers.image.source. L'instantané doit donc
# exister avant la construction de l'image, jamais après.
PUBLIC_EXCLUDE        ?= .github
PUBLIC_BRANCH         ?= main
SNAPSHOT_BRANCH       ?= public-snapshot
SNAPSHOT_MESSAGE_FILE ?= .github/public-snapshot.md

release: version-check
	@test -z "$$(git status --porcelain)" || { \
		echo "Arbre de travail modifié : publiez depuis un état propre."; exit 1; }
	@set -e; \
	trap 'git checkout -f -q $(PUBLIC_BRANCH) 2>/dev/null || true; \
	      git branch -q -D $(SNAPSHOT_BRANCH) 2>/dev/null || true' EXIT; \
	git tag -f -a v$(IMAGE_TAG) -m "Release $(IMAGE_TAG)" >/dev/null; \
	git push $(GIT_PRIVATE_REMOTE) $(PUBLIC_BRANCH); \
	git push -f $(GIT_PRIVATE_REMOTE) v$(IMAGE_TAG); \
	git checkout -q --orphan $(SNAPSHOT_BRANCH); \
	git rm -r -q --cached $(PUBLIC_EXCLUDE); \
	git commit -q -F $(SNAPSHOT_MESSAGE_FILE); \
	snapshot=$$(git rev-parse HEAD); \
	git push -f $(GIT_PUBLIC_REMOTE) $$snapshot:refs/heads/$(PUBLIC_BRANCH); \
	git push -f $(GIT_PUBLIC_REMOTE) $$snapshot:refs/tags/v$(IMAGE_TAG); \
	git checkout -f -q $(PUBLIC_BRANCH); \
	git branch -q -D $(SNAPSHOT_BRANCH); \
	echo "Instantané public : $$snapshot"; \
	$(MAKE) --no-print-directory docker-push BUILD_COMMIT=$$snapshot

# Deux étiquettes seulement : la version et latest. Un doublon préfixé « v »
# désignerait la même image sous un second nom, sans rien apporter, et se
# périmerait dès la publication suivante s'il n'était pas repoussé en même temps.
docker-push: docker-build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_USER)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_USER)/$(IMAGE_NAME):latest
	docker push $(DOCKER_USER)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(DOCKER_USER)/$(IMAGE_NAME):latest

clean:
	rm -rf bin/
