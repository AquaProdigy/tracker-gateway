FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY build/libs/*.jar tracker-gateway-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","/app/tracker-gateway-0.0.1-SNAPSHOT.jar"]