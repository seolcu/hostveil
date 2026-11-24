# The release image, with its Alpine packages brought up to date.
FROM adminer:5
USER root
RUN apk upgrade --no-cache
USER adminer
