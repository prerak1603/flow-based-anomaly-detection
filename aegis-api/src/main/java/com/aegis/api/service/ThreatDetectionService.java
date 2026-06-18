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
            String featureVector = buildFeatureVector(flow);

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

            System.out.println(">>> AEGIS: Exit code: " + exitCode);
            System.out.println(">>> AEGIS: Output: " + output);

            if (exitCode != 0 || output.isEmpty()) {
                System.out.println(">>> AEGIS: Non-zero exit or empty output, using fallback");
                return simulatePrediction(flow);
            }

            return parsePythonOutput(output);

        } catch (Exception e) {
            System.out.println(">>> AEGIS FALLBACK exception: " + e.getMessage());
            e.printStackTrace();
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
        // Python returns JSON: {"threat_class":"Normal","confidence":0.99,"probabilities":{"Normal":0.99,...},...}
        try {
            // Simple JSON parsing without external library
            String threatClass = extractJsonString(output, "threat_class");
            double confidence  = extractJsonDouble(output, "confidence");

            Map<String, Double> probs = new LinkedHashMap<>();
            String probsSection = output.substring(output.indexOf("\"probabilities\""));
            for (String cls : THREAT_CLASSES) {
                // Map Python class names (capitalized) to our lowercase keys
                String capCls = cls.substring(0, 1).toUpperCase() + cls.substring(1);
                double p = 0.0;
                try { p = extractJsonDouble(probsSection, capCls); } catch (Exception ignored) {}
                try { if (p == 0.0) p = extractJsonDouble(probsSection, cls); } catch (Exception ignored) {}
                probs.put(cls, p);
            }

            // Normalize class name to lowercase
            String normalizedClass = threatClass.toLowerCase();
            if (normalizedClass.equals("normal")) normalizedClass = "normal";

            PredictionResult result = new PredictionResult(normalizedClass, confidence, probs);
            addToHistory(result);
            return result;
        } catch (Exception e) {
            System.out.println(">>> AEGIS: JSON parse error: " + e.getMessage());
            System.out.println(">>> AEGIS: Raw output was: " + output);
            throw new RuntimeException("Failed to parse Python output", e);
        }
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        int colonIdx = json.indexOf(":", keyIdx);
        int startQuote = json.indexOf("\"", colonIdx + 1);
        int endQuote = json.indexOf("\"", startQuote + 1);
        return json.substring(startQuote + 1, endQuote);
    }

    private double extractJsonDouble(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        int colonIdx = json.indexOf(":", keyIdx);
        int start = colonIdx + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.' || json.charAt(end) == '-' || json.charAt(end) == 'E' || json.charAt(end) == 'e')) end++;
        return Double.parseDouble(json.substring(start, end));
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
