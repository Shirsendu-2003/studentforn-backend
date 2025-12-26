# -------- Build Stage --------
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Copy Maven wrapper
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# ✅ FIX: make mvnw executable
RUN chmod +x mvnw

# Download dependencies (cache layer)
RUN ./mvnw dependency:go-offline

# Copy source & build
COPY src src
RUN ./mvnw clean package -DskipTests

# -------- Runtime Stage --------
FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENV TZ=Asia/Kolkata
EXPOSE 8080

ENTRYPOINT ["java","-XX:+UseContainerSupport","-jar","app.jar"]
