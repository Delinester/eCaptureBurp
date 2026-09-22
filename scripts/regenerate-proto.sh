#!/usr/bin/env bash
#
# Re-generates the Java protobuf stubs for the eCaptureBurp extension from the
# .proto kept in src/main/proto/ecaptureq.proto.
#
# When gojue/ecapture changes its schema (protobuf/proto/v1/ecaptureq.proto in
# the ecapture repo), copy the updated file over src/main/proto/ecaptureq.proto
# (keeping the java_package / java_multiple_files / java_outer_classname
# options), then run this script and rebuild with ./gradlew jar.
#
# The protoc version MUST match the com.google.protobuf:protobuf-java version
# in build.gradle (currently 3.25.1 -> protoc v25.1). If you bump the runtime
# dependency, bump protoc to the matching release from
# https://github.com/protocolbuffers/protobuf/releases
#
set -euo pipefail

cd "$(dirname "$0")/.."

PROTOC="${PROTOC:-protoc}"
if ! command -v "$PROTOC" >/dev/null 2>&1; then
    echo "protoc not found. Install it, or set PROTOC=/path/to/protoc (v25.1)." >&2
    exit 1
fi

"$PROTOC" -I src/main/proto --java_out=src/main/java src/main/proto/ecaptureq.proto

echo "Generated protobuf stubs in src/main/java/com/ecapture/burp/proto/"
echo "Now fix any compile errors in ECaptureWebSocketClient.java and run: ./gradlew jar"
