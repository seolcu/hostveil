# The release image, with its Alpine packages brought up to date.
FROM redis:7-alpine
RUN apk upgrade --no-cache
