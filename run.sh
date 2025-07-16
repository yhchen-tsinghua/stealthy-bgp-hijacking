#!/usr/bin/env bash
set -e

IMAGE_NAME="ndss26/ae20:latest"
IMAGE_TAR="docker-image.tar.gz"
CONTAINER_NAME="ndss26ae20"
DOCKER="docker"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Check if Docker is available without sudo
if ! docker ps >/dev/null 2>&1; then
    if command -v sudo >/dev/null && sudo docker ps >/dev/null 2>&1; then
        echo "Docker requires sudo. Switching to 'sudo docker'."
        DOCKER="sudo docker"
    else
        echo "Error: Docker is not available or you don't have permission to run it."
        echo "Please ensure Docker is installed and your user is in the 'docker' group."
        exit 1
    fi
fi

# Check if image exists
if ! $DOCKER image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Image '$IMAGE_NAME' not found. Loading from $IMAGE_TAR..."
    if [ -f "$IMAGE_TAR" ]; then
        $DOCKER load -i "$IMAGE_TAR"
        echo "Image loaded successfully."
    else
        echo "Error: $IMAGE_TAR not found. Cannot proceed."
        exit 1
    fi
else
    echo "Image '$IMAGE_NAME' already loaded."
fi

# Use appropriate docker compose command (with or without sudo)
DOCKER_COMPOSE="$DOCKER compose"

# Use NVIDIA GPU or not
echo "Detecting NVIDIA GPU support..."
if command -v nvidia-smi &> /dev/null && docker info | grep -i 'nvidia' &> /dev/null; then
    echo "NVIDIA GPU detected and Docker runtime is ready."
    DOCKER_COMPOSE_CONFIG="docker-compose-gpu.yml"
else
    echo "No usable NVIDIA GPU or runtime detected. Falling back to CPU."
    DOCKER_COMPOSE_CONFIG="docker-compose.yml"
fi

echo "Launching container..."
$DOCKER_COMPOSE -f $DOCKER_COMPOSE_CONFIG run --rm --service-ports "$CONTAINER_NAME"
