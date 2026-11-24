# The release image, with its Alpine packages brought up to date, serving one
# page. nginx-unprivileged runs as uid 101 and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.31-alpine
USER root
RUN apk upgrade --no-cache
COPY index.html /usr/share/nginx/html/index.html
USER 101
