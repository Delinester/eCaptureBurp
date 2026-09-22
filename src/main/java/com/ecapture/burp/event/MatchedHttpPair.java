package com.ecapture.burp.event;

/**
 * Represents a matched HTTP request-response pair.
 */
public class MatchedHttpPair {
    
    private final String uuid;
    private volatile CapturedEvent request;
    private volatile CapturedEvent response;
    private final long createdAt;
    private boolean sentToProxy;
    
    public MatchedHttpPair(String uuid) {
        this.uuid = uuid;
        this.createdAt = System.currentTimeMillis();
        this.sentToProxy = false;
    }
    
    public String getUuid() {
        return uuid;
    }
    
    public CapturedEvent getRequest() {
        return request;
    }
    
    public void setRequest(CapturedEvent request) {
        this.request = request;
    }
    
    public CapturedEvent getResponse() {
        return response;
    }
    
    public void setResponse(CapturedEvent response) {
        this.response = response;
    }
    
    public boolean hasRequest() {
        return request != null;
    }
    
    public boolean hasResponse() {
        return response != null;
    }
    
    public boolean isComplete() {
        return hasRequest() && hasResponse();
    }
    
    public long getCreatedAt() {
        return createdAt;
    }
    
    public boolean isSentToProxy() {
        return sentToProxy;
    }
    
    public void setSentToProxy(boolean sentToProxy) {
        this.sentToProxy = sentToProxy;
    }
    
    /**
     * Get display timestamp (from request if available, otherwise response)
     */
    public String getTimestamp() {
        try {
            if (request != null) {
                return request.getFormattedTimestamp();
            } else if (response != null) {
                return response.getFormattedTimestamp();
            }
        } catch (Exception e) {
            // Timestamp conversion failed
        }
        // Fallback to current time
        return java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
    
    /**
     * Get HTTP method from request
     */
    public String getMethod() {
        return request != null ? request.getHttpMethod() : "-";
    }
    
    /**
     * Get URL from request
     */
    public String getUrl() {
        return request != null ? request.getUrl() : "-";
    }
    
    /**
     * Get host from request
     */
    public String getHost() {
        if (request != null) {
            return request.getHost();
        } else if (response != null) {
            return response.getDstIp();
        }
        return "-";
    }
    
    /**
     * Get status code from response
     */
    public String getStatusCode() {
        return response != null ? response.getStatusCode() : "-";
    }
    
    /**
     * Get request length
     */
    public int getRequestLength() {
        return request != null ? request.getLength() : 0;
    }
    
    /**
     * Get response length
     */
    public int getResponseLength() {
        return response != null ? response.getLength() : 0;
    }
    
    /**
     * Get process info
     */
    public String getProcessInfo() {
        if (request != null) {
            return request.getProcessName() + " (" + request.getPid() + ")";
        } else if (response != null) {
            return response.getProcessName() + " (" + response.getPid() + ")";
        }
        return "-";
    }
    
    /**
     * Get destination port (typically the server port)
     */
    public int getPort() {
        try {
            int explicit = java.net.URI.create("https://" + getHost()).getPort();
            if (explicit > 0) return explicit;
        } catch (IllegalArgumentException ignored) {}
        if (request != null) {
            if (request.getDstPort() > 0) return request.getDstPort();
            if ("http".equals(request.getScheme()) || request.getUrl().startsWith("http://")) return 80;
        } else if (response != null) {
            if (response.getSrcPort() > 0) return response.getSrcPort();
        }
        return 443;
    }

    public String getServiceHost() {
        try {
            String host = java.net.URI.create("https://" + getHost()).getHost();
            if (host != null) return host;
        } catch (IllegalArgumentException ignored) {}
        return getHost();
    }
    
    /**
     * Check if this is HTTPS (based on port heuristics)
     */
    public boolean isHttps() {
        if (request != null) {
            if ("http".equals(request.getScheme()) || request.getUrl().startsWith("http://")) return false;
            if ("https".equals(request.getScheme()) || request.getUrl().startsWith("https://")) return true;
        }
        int port = getPort();
        return port != 80; // TLS plaintext feed; scheme metadata wins where available.
    }
    
    @Override
    public String toString() {
        return String.format("MatchedHttpPair[uuid=%s, method=%s, url=%s, status=%s, complete=%s]",
                uuid, getMethod(), getUrl(), getStatusCode(), isComplete());
    }
}
