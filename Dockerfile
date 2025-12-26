# -------- Build Stage --------
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Copy Maven files first (for cache)
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn
RUN ./mvnw dependency:go-offline

# Copy source and build
COPY src src
RUN ./mvnw clean package -DskipTests

# -------- Runtime Stage --------
FROM eclipse-temurin:21-jre
WORKDIR /app

# Copy built JAR
COPY --from=build /app/target/*.jar app.jar

# Set timezone (India)
ENV TZ=Asia/Kolkata

# Expose app port
EXPOSE 8080

# Run app
ENTRYPOINT ["java","-XX:+UseContainerSupport","-jar","app.jar"]
