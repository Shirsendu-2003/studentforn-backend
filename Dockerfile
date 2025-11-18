# ---- build stage ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
RUN chmod +x mvnw

RUN ./mvnw -B -ntp dependency:go-offline

COPY src ./src
RUN ./mvnw -B -DskipTests clean package


# ---- runtime stage ----
FROM eclipse-temurin:21-jre
WORKDIR /app

# Install curl for healthcheck
USER root
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Add non-root user (optional)
RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup
USER appuser

COPY --from=build /workspace/target/*.jar app.jar

# Use Render's dynamic PORT
ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT}/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java -jar /app/app.jar --server.port=${PORT}"]
