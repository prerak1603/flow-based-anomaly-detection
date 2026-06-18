# Stage 1: Build Java
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install joblib scikit-learn xgboost lightgbm numpy pandas

COPY --from=build /app/target/*.jar app.jar
COPY src/main/resources/predict.py predict.py
COPY src/main/resources/models/ models/

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
