FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jre xvfb xauth libsdl2-2.0-0 procps binutils && rm -rf /var/lib/apt/lists/*
RUN python -m pip --version && java -version && ! command -v gcc && ! command -v make
