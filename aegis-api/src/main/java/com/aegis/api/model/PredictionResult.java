package com.aegis.api.model;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Represents the result of a single threat classification prediction.
 */
public class PredictionResult {

    private String threatClass;
    private double confidence;
    private Map<String, Double> classProbabilities;
    private String severity;
    private LocalDateTime timestamp;
    private String message;

    public PredictionResult() {
        this.timestamp = LocalDateTime.now();
    }

    public PredictionResult(String threatClass, double confidence,
                             Map<String, Double> classProbabilities) {
        this.threatClass        = threatClass;
        this.confidence         = confidence;
        this.classProbabilities = classProbabilities;
        this.severity           = resolveSeverity(threatClass);
        this.timestamp          = LocalDateTime.now();
        this.message            = buildMessage(threatClass, confidence);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String resolveSeverity(String threatClass) {
        return switch (threatClass.toLowerCase()) {
            case "normal"  -> "NONE";
            case "dos"     -> "HIGH";
            case "probe"   -> "MEDIUM";
            case "r2l"     -> "HIGH";
            case "u2r"     -> "CRITICAL";
            default        -> "UNKNOWN";
        };
    }

    private String buildMessage(String threatClass, double confidence) {
        if (threatClass.equalsIgnoreCase("normal")) {
            return "Traffic classified as normal. No threat detected.";
        }
        return String.format("⚠ Threat detected: %s (confidence: %.1f%%). Immediate review recommended.",
                threatClass.toUpperCase(), confidence * 100);
    }

    // ── Getters & Setters ────────────────────────────────────────────────────

    public String getThreatClass() { return threatClass; }
    public void setThreatClass(String threatClass) { this.threatClass = threatClass; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public Map<String, Double> getClassProbabilities() { return classProbabilities; }
    public void setClassProbabilities(Map<String, Double> classProbabilities) { this.classProbabilities = classProbabilities; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}
