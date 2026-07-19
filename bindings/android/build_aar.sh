
#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Navigate to the Android bindings directory
cd "$(dirname "$0")"

echo "Building Android Archive (AAR) for hardware-trust-engine..."

# Clean previous builds
./gradlew clean

# Build the release AAR
# The `assembleRelease` task will build for all specified ABIs (arm64-v8a, x86_64)
./gradlew assembleRelease

echo "Android AAR build complete. AAR files can be found in build/outputs/aar/"
