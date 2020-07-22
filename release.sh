# Update version to release version with
export JAR_VERSION=$VERSION
# Update version information in 2 readme.md to new version

gradle clean build artifactoryPublish --no-daemon
