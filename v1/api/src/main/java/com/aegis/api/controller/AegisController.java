package com.aegis.api.controller;

import com.aegis.api.model.NetworkFlow;
import com.aegis.api.model.PredictionResult;
import com.aegis.api.service.ThreatDetectionService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST Controller exposing Aegis AI threat detection endpoints.
 *
 * Endpoints:
 *   POST   /api/predict          — classify a network flow
 *   GET    /api/history?limit=N  — get last N predictions
 *   GET    /api/stats            — threat distribution summary
 *   DELETE /api/history          — clear history
 *   GET    /api/health           — health check
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AegisController {

    private final ThreatDetectionService detectionService;

    public AegisController(ThreatDetectionService detectionService) {
        this.detectionService = detectionService;
    }

    /**
     * Classifies a network flow and returns the threat prediction.
     *
     * Example request body:
     * {
     *   "duration": 0,
     *   "protocolType": "tcp",
     *   "service": "http",
     *   "flag": "SF",
     *   "srcBytes": 232,
     *   "dstBytes": 8153
     * }
     */
    @PostMapping("/predict")
    public ResponseEntity<PredictionResult> predict(@Valid @RequestBody NetworkFlow flow) {
        try {
            PredictionResult result = detectionService.classify(flow);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            PredictionResult error = new PredictionResult();
            error.setThreatClass("ERROR");
            error.setMessage("Prediction failed: " + e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }

    /**
     * Returns the last N predictions from in-memory history.
     * Defaults to last 10 if no limit specified.
     */
    @GetMapping("/history")
    public ResponseEntity<List<PredictionResult>> getHistory(
            @RequestParam(defaultValue = "10") int limit) {
        return ResponseEntity.ok(detectionService.getHistory(limit));
    }

    /**
     * Returns threat class distribution and detection stats.
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(detectionService.getStats());
    }

    /**
     * Clears prediction history.
     */
    @DeleteMapping("/history")
    public ResponseEntity<Map<String, String>> clearHistory() {
        detectionService.clearHistory();
        return ResponseEntity.ok(Map.of("message", "Prediction history cleared."));
    }

    /**
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status",  "UP",
                "service", "Aegis AI Threat Detection API",
                "version", "1.0.0"
        ));
    }
}
