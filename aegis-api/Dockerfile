# Stage 1: Build the Java application
FROM maven:3.9.6-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml first (for dependency caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the jar, skip tests
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Install Python and required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python ML dependencies
RUN pip3 install --break-system-packages \
    joblib \
    scikit-learn \
    xgboost \
    lightgbm \
    numpy \
    pandas \
    warnings

# Copy the built jar from Stage 1
COPY --from=build /app/target/*.jar app.jar

# Copy predict.py
COPY src/main/resources/predict.py predict.py

# Expose port
EXPOSE 8080

# Set environment variable for model path
ENV MODEL_DIR=/app/models

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
