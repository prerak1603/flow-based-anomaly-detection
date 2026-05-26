package com.aegis.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aegis AI — Spring Boot REST API
 * Serves the Phase 2 ensemble ML model as a live threat detection service.
 */
@SpringBootApplication
public class AegisApplication {
    public static void main(String[] args) {
        SpringApplication.run(AegisApplication.class, args);
    }
}
