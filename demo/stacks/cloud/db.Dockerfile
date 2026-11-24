# The release image, with its Alpine packages brought up to date. The service
# runs as the postgres user, so the entrypoint never switches users and gosu
# (a Go binary carrying its own copy of an old standard library) is not
# needed in the image.
FROM postgres:17-alpine
RUN apk upgrade --no-cache && rm -f /usr/local/bin/gosu
