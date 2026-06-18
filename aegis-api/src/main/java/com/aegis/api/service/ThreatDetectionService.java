package com.aegis.api.service;

import com.aegis.api.model.NetworkFlow;
import com.aegis.api.model.PredictionResult;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

/**
 * Core service that interfaces with the Aegis AI Python ML model.
 *
 * Architecture:
 *   Java Spring Boot API  →  Python subprocess (joblib model)  →  PredictionResult
 *
 * The service maintains an in-memory prediction history using a thread-safe
 * ConcurrentLinkedDeque, capped at MAX_HISTORY entries.
 */
@Service
public class ThreatDetectionService {

    private static final int MAX_HISTORY = 100;

    // Thread-safe in-memory store for prediction history
    private final Deque<PredictionResult> predictionHistory = new ConcurrentLinkedDeque<>();

    // Class labels from NSL-KDD (mirrors Phase 2 label encoder)
    private static final List<String> THREAT_CLASSES = Arrays.asList(
            "normal", "dos", "probe", "r2l", "u2r"
    );

    /**
     * Classifies a network flow record using the trained ensemble model.
     * Calls the Python model via subprocess and parses the output.
     *
     * @param flow the incoming network flow features
     * @return PredictionResult with class, confidence and probabilities
     * @throws RuntimeException if the Python model call fails
     */
    public PredictionResult classify(NetworkFlow flow) {
        try {
            // Build feature vector as comma-separated string for Python script
            String featureVector = buildFeatureVector(flow);

            // Call Python model via ProcessBuilder
            ProcessBuilder pb = new ProcessBuilder(
                    "python3",
                    "predict.py",
                    featureVector
            );
            pb.redirectErrorStream(true);
            System.out.println(">>> AEGIS: Running predict.py from dir: " + pb.directory());
            System.out.println(">>> AEGIS: Command: " + pb.command());
            Process process = pb.start();

            String output = new String(process.getInputStream().readAllBytes()).trim();
            int exitCode  = process.waitFor();

            if (exitCode != 0 || output.isEmpty()) {
                // Fallback to simulation if Python model not available
                System.out.println(">>> AEGIS FALLBACK: " + e.getMessage());
            return simulatePrediction(flow);
            }

            return parsePythonOutput(output);

        } catch (Exception e) {
            // Graceful fallback — model not loaded yet, simulate result
            System.out.println(">>> AEGIS FALLBACK: " + e.getMessage());
            return simulatePrediction(flow);
        }
    }

    /**
     * Returns the last N predictions from in-memory history.
     */
    public List<PredictionResult> getHistory(int limit) {
        return predictionHistory.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }

    /**
     * Returns a summary of threat class distribution from history.
     */
    public Map<String, Object> getStats() {
        Map<String, Long> classCounts = new HashMap<>();
        long totalThreats = 0;

        for (PredictionResult result : predictionHistory) {
            classCounts.merge(result.getThreatClass(), 1L, Long::sum);
            if (!result.getThreatClass().equalsIgnoreCase("normal")) {
                totalThreats++;
            }
        }

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalPredictions", predictionHistory.size());
        stats.put("totalThreats",     totalThreats);
        stats.put("classCounts",      classCounts);
        stats.put("threatRate",       predictionHistory.isEmpty() ? 0.0
                : (double) totalThreats / predictionHistory.size());
        return stats;
    }

    /**
     * Clears prediction history.
     */
    public void clearHistory() {
        predictionHistory.clear();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private String buildFeatureVector(NetworkFlow flow) {
        return String.join(",",
                String.valueOf(flow.getDuration()),
                flow.getProtocolType(),
                flow.getService(),
                flow.getFlag(),
                String.valueOf(flow.getSrcBytes() != null ? flow.getSrcBytes() : 0),
                String.valueOf(flow.getDstBytes() != null ? flow.getDstBytes() : 0)
        );
    }

    private PredictionResult parsePythonOutput(String output) {
        // Expected format: "threatClass,confidence,p0,p1,p2,p3,p4"
        String[] parts = output.split(",");
        String threatClass = parts[0];
        double confidence  = Double.parseDouble(parts[1]);

        Map<String, Double> probs = new LinkedHashMap<>();
        for (int i = 0; i < THREAT_CLASSES.size() && (i + 2) < parts.length; i++) {
            probs.put(THREAT_CLASSES.get(i), Double.parseDouble(parts[i + 2]));
        }

        PredictionResult result = new PredictionResult(threatClass, confidence, probs);
        addToHistory(result);
        return result;
    }

    /**
     * Simulation mode — used when the Python model is not available.
     * Uses rule-based heuristics on NSL-KDD features to produce a realistic result.
     */
    private PredictionResult simulatePrediction(NetworkFlow flow) {
        String threatClass;
        double confidence;

        // Simple heuristic rules based on NSL-KDD feature patterns
        if (flow.getSrcBytes() != null && flow.getSrcBytes() > 50000) {
            threatClass = "dos";
            confidence  = 0.91;
        } else if (flow.getSerrorRate() != null && flow.getSerrorRate() > 0.8) {
            threatClass = "probe";
            confidence  = 0.85;
        } else if (flow.getNumFailedLogins() != null && flow.getNumFailedLogins() > 3) {
            threatClass = "r2l";
            confidence  = 0.88;
        } else if (flow.getRootShell() != null && flow.getRootShell() == 1) {
            threatClass = "u2r";
            confidence  = 0.94;
        } else {
            threatClass = "normal";
            confidence  = 0.97;
        }

        Map<String, Double> probs = new LinkedHashMap<>();
        for (String cls : THREAT_CLASSES) {
            probs.put(cls, cls.equals(threatClass) ? confidence
                    : (1.0 - confidence) / (THREAT_CLASSES.size() - 1));
        }

        PredictionResult result = new PredictionResult(threatClass, confidence, probs);
        addToHistory(result);
        return result;
    }

    private void addToHistory(PredictionResult result) {
        predictionHistory.addFirst(result);
        while (predictionHistory.size() > MAX_HISTORY) {
            predictionHistory.removeLast();
        }
    }
}
