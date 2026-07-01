FROM alpine:3.20

RUN apk add --no-cache openssl

WORKDIR /project

ENTRYPOINT ["/bin/sh", "/project/scripts/entrypoint.sh"]
CMD ["generate"]