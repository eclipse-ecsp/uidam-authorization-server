#FROM artifactory-fr.harman.com:5067/ignite-core/ignite-api-base-java17-tomcat10-apr:1.1.0-4
FROM azul/zulu-openjdk-alpine:25-latest
WORKDIR /app

EXPOSE 8080

ENV LOG_DIR=/app/logs
ENV MICROSERVICE_NAME=uidam-authorization-server

ARG PROJECT_JAR_NAME

ENV PROJECT_JAR_NAME ${PROJECT_JAR_NAME}

COPY target/${PROJECT_JAR_NAME}.jar /app/

COPY src/main/resources /app/config
COPY docker-entrypoint.sh /app/
COPY uidamauthserver.jks /app/

RUN mkdir -p /tmp/customui
COPY src/main/resources/templates /tmp/customui/templates
COPY src/main/resources/static /tmp/customui/static

# Run microservice as non root user
RUN chmod +x ./docker-entrypoint.sh && \
  addgroup -g 1010 msuser && \
  adduser -S -u 1010 -G msuser msuser && \
  chown -R msuser:msuser /app /tmp
USER msuser

ENTRYPOINT ["./docker-entrypoint.sh"]
