# ============================
#  Build Stage
# ============================
FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
RUN chmod +x mvnw

# Download dependencies
RUN ./mvnw -B -ntp dependency:go-offline

# Copy source code
COPY src ./src

# Build project
RUN ./mvnw -B -DskipTests clean package


# ============================
#  Runtime Stage
# ============================
FROM eclipse-temurin:21-jre
WORKDIR /app

# Install curl for health checks
USER root
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Add non-root user
RUN addgroup --system appgroup && adduser --system appuser --ingroup appgroup
USER appuser

COPY --from=build /workspace/target/*.jar app.jar

# Render will inject PORT automatically
ENV PORT=$PORT

# Expose the dynamic port
EXPOSE ${PORT}

# Health check (works on Render)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -f http://localhost:${PORT}/actuator/health || exit 1

# Start Spring Boot with Render's injected PORT
ENTRYPOINT ["sh", "-c", "java -jar app.jar --server.port=${PORT}"]
