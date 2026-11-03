#!/usr/bin/env bash
# Bring the stack up from a genuinely clean state.
#
# `docker compose down -v` removes a project volume only if nothing else holds it
# open. A container started outside compose with `-v docker_builds:…` (a manual
# beacon, a debugging shell) silently keeps the volume alive, and the next deploy
# then reports success while `setup` skips the rebuild — because the old artifacts
# are still there. That is how a stack ends up running a binary from three
# deployments ago.
#
# This script makes the wipe verifiable: remove foreign holders, run down -v
# without hiding its output, then assert no project volume survives.
set -euo pipefail

# scripts/deploy-fresh.sh -> docker/ -> project root. Two levels, not one: one
# level lands in docker/ and the compose path below then resolves to
# docker/docker/docker-compose.yml.
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
COMPOSE=${COMPOSE:-"docker compose -f docker/docker-compose.yml"}
PROJECT_PREFIX=${PROJECT_PREFIX:-docker_}

step() { printf '\n== %s\n' "$*"; }

step "checking for containers outside compose that hold project volumes"
mapfile -t volumes < <(docker volume ls --format '{{.Name}}' | grep "^${PROJECT_PREFIX}" || true)
if [ ${#volumes[@]} -eq 0 ]; then
    echo "no project volumes present"
else
    for volume in "${volumes[@]}"; do
        mapfile -t holders < <(docker ps -aq --filter "volume=${volume}" || true)
        for holder in "${holders[@]}"; do
            name=$(docker inspect -f '{{.Name}}' "$holder" | sed 's|^/||')
            case "$name" in
                archon|dns1|dns2|client|http-client|http-client-default|setup) continue ;;
            esac
            echo "removing ${name} (holds ${volume})"
            docker rm -f "$name" >/dev/null
        done
    done
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    printf '\nDRY_RUN=1: stopping before down -v. Project volumes that would be removed:\n'
    docker volume ls --format '{{.Name}}' | grep "^${PROJECT_PREFIX}" || echo "  (none)"
    exit 0
fi

step "stopping the stack and removing its volumes"
# Output is deliberately not suppressed: a failure here is the whole point.
$COMPOSE down -v --remove-orphans

step "verifying the volumes are gone"
remaining=$(docker volume ls --format '{{.Name}}' | grep "^${PROJECT_PREFIX}" || true)
if [ -n "$remaining" ]; then
    echo "ERROR: volumes survived down -v:" >&2
    echo "$remaining" >&2
    echo "Something still holds them. Refusing to continue: a deploy on stale" >&2
    echo "volumes silently skips the rebuild." >&2
    exit 1
fi

step "starting archon"
$COMPOSE up -d archon
for _ in $(seq 1 60); do
    if curl -ks https://127.0.0.1:8443/login -o /dev/null 2>/dev/null; then break; fi
    sleep 2
done

step "building the runtime binaries (setup)"
$COMPOSE up -d setup
for _ in $(seq 1 240); do
    state=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' setup 2>/dev/null || echo "missing")
    case "$state" in
        exited*) echo "setup: $state"; break ;;
    esac
    sleep 5
done
state=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' setup 2>/dev/null || echo "missing")
if [ "$state" != "exited 0" ]; then
    echo "ERROR: setup did not complete cleanly ($state). Logs:" >&2
    docker logs --tail 30 setup >&2 || true
    exit 1
fi

step "starting the services"
$COMPOSE up -d --no-deps dns1 dns2 client http-client http-client-default
sleep 20
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'archon|dns1|dns2|client' || true

printf '\nStack is up. Dashboard: https://<host>:8443\n'
