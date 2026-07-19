
#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Navigate to the Swift bindings directory
cd "$(dirname "$0")"

# Define output directory
XCFRAMEWORK_OUTPUT_DIR="./build"
mkdir -p "${XCFRAMEWORK_OUTPUT_DIR}"

# Define the name of your library
LIBRARY_NAME="HardwareTrustEngine"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}.xcframework"
rm -rf "./build/"*.build

# Build for iOS devices (iphoneos)
echo "Building for iOS devices (iphoneos)..."
xcodebuild archive \
    -scheme "${LIBRARY_NAME}" \
    -destination "generic/platform=iOS" \
    -archivePath "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphoneos.xcarchive" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARIES_FOR_DISTRIBUTION=YES

# Build for iOS simulator (iphonesimulator)
echo "Building for iOS simulator (iphonesimulator)..."
xcodebuild archive \
    -scheme "${LIBRARY_NAME}" \
    -destination "generic/platform=iOS Simulator" \
    -archivePath "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphonesimulator.xcarchive" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARIES_FOR_DISTRIBUTION=YES

# Create XCFramework
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -archive "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphoneos.xcarchive" -framework "${LIBRARY_NAME}.framework" \
    -archive "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphonesimulator.xcarchive" -framework "${LIBRARY_NAME}.framework" \
    -output "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}.xcframework"

echo "XCFramework created at: ${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}.xcframework"

# Clean up intermediate archives
rm -rf "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphoneos.xcarchive"
rm -rf "${XCFRAMEWORK_OUTPUT_DIR}/${LIBRARY_NAME}-iphonesimulator.xcarchive"

echo "Build process complete."
