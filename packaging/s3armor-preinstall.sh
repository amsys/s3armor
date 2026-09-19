#!/bin/sh
# apk preinstall script. Alpine has no DynamicUser, so the package makes a
# fixed system user and group. The OpenRC service runs as this user.
addgroup -S s3armor 2>/dev/null || true
adduser -S -D -H -h /nonexistent -s /sbin/nologin -G s3armor s3armor 2>/dev/null || true
