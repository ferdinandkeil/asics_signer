# syntax=docker/dockerfile:1
# Build-Stage: Maven (Netzzugriff nur hier, fuer Maven Central)
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests

# Laufzeit-Stage: nur JRE, kein Netz noetig
FROM eclipse-temurin:21-jre@sha256:ca73b4d3961703d6d7830a4361f49ef0478f8f28b39defc07bb72f4cc7f834f6
RUN useradd -r -u 10001 dss
COPY --from=build /src/target/asics-dss.jar /app/asics-dss.jar
COPY --from=build /src/target/lib /app/lib
COPY policy/ /app/policy/
USER dss
ENTRYPOINT ["java", "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn", "-jar", "/app/asics-dss.jar"]
