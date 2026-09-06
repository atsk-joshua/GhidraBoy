# Build this separately from the retained native-decompiler builder image.
# The base image is a locally retained, qualified image, not a pullable digest.
FROM ghidraboy-native-dependency-builder:12.1.3-index1-jammy
USER root
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
