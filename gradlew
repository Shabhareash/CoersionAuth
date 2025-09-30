#!/usr/bin/env sh

# Gradle wrapper for *nix
APP_HOME=$(cd "$(dirname "$0")"; pwd -P)

DEFAULT_JVM_OPTS=""

CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"

if [ ! -f "$CLASSPATH" ]; then
  echo "Gradle wrapper JAR not found at $CLASSPATH."
  echo "You can install Gradle locally and run: gradle wrapper --gradle-version 8.7"
  exit 1
fi

exec "${JAVA_HOME}/bin/java" ${DEFAULT_JVM_OPTS} -classpath "$CLASSPATH" org.gradle.wrapper.GradleWrapperMain "$@"
