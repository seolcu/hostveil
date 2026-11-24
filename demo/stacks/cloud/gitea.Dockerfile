# The release image, with the Alpine packages it was built on brought up to
# date: an image published last month carries last month's packages.
FROM gitea/gitea:28.4-rootless
USER root
RUN apk upgrade --no-cache
USER 1000:1000
