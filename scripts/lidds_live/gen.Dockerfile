# Generic normal-traffic generator for pulse-live-lidds-v1 (one image, imported to the workers).
FROM python:3.12-alpine
RUN apk add --no-cache curl mariadb-client bash
ENTRYPOINT ["/bin/sh"]
