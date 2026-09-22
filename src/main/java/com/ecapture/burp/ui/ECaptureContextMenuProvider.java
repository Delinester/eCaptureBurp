package com.ecapture.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.ecapture.burp.event.CapturedEvent;
import com.ecapture.burp.event.MatchedHttpPair;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides context menu items for sending captured requests to Repeater.
 */
public class ECaptureContextMenuProvider implements ContextMenuItemsProvider {
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ECaptureTab tab;
    
    public ECaptureContextMenuProvider(MontoyaApi api, ECaptureTab tab) {
        this.api = api;
        this.logging = api.logging();
        this.tab = tab;
        
        // Add mouse listener to the table for right-click menu
        setupTableContextMenu();
    }
    
    private void setupTableContextMenu() {
        JTable table = tab.getEventTable();
        
        JPopupMenu popupMenu = new JPopupMenu();
        
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        popupMenu.add(sendToRepeater);
        
        popupMenu.addSeparator();
        
        JMenuItem copyRequest = new JMenuItem("Copy Request");
        copyRequest.addActionListener(e -> copySelectedRequest());
        popupMenu.add(copyRequest);
        
        JMenuItem copyResponse = new JMenuItem("Copy Response");
        copyResponse.addActionListener(e -> copySelectedResponse());
        popupMenu.add(copyResponse);
        
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copySelectedUrl());
        popupMenu.add(copyUrl);
        
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }
            
            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }
            
            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && row < table.getRowCount()) {
                        table.setRowSelectionInterval(row, row);
                    }
                    
                    MatchedHttpPair pair = tab.getSelectedPair();
                    boolean hasRequest = pair != null && pair.hasRequest();
                    boolean hasResponse = pair != null && pair.hasResponse();
                    
                    sendToRepeater.setEnabled(hasRequest);
                    copyRequest.setEnabled(hasRequest);
                    copyResponse.setEnabled(hasResponse);
                    copyUrl.setEnabled(hasRequest);
                    
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }
    
    /**
     * Send selected request to Burp Repeater.
     */
    private void sendSelectedToRepeater() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        
        try {
            HttpRequest request = buildHttpRequest(pair);
            if (request != null) {
                String tabName = pair.getMethod() + " " + pair.getUrl();
                if (tabName.length() > 50) {
                    tabName = tabName.substring(0, 47) + "...";
                }
                api.repeater().sendToRepeater(request, tabName);
            } else {
                logging.logToError("Failed to build HTTP request for Repeater");
                JOptionPane.showMessageDialog(tab.getEventTable(),
                        "Failed to build HTTP request. Host information may be missing.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            logging.logToError("Error sending to Repeater: " + e.getMessage());
            e.printStackTrace();
            JOptionPane.showMessageDialog(tab.getEventTable(),
                    "Error sending to Repeater: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Copy selected request to clipboard.
     */
    private void copySelectedRequest() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        
        CapturedEvent request = pair.getRequest();
        if (request.getPayload() != null) {
            String requestStr = new String(request.getPayload());
            copyToClipboard(requestStr);
        }
    }
    
    /**
     * Copy selected response to clipboard.
     */
    private void copySelectedResponse() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasResponse()) {
            return;
        }
        
        CapturedEvent response = pair.getResponse();
        if (response.getPayload() != null) {
            String responseStr = new String(response.getPayload());
            copyToClipboard(responseStr);
        }
    }
    
    /**
     * Copy URL to clipboard.
     */
    private void copySelectedUrl() {
        MatchedHttpPair pair = tab.getSelectedPair();
        if (pair == null || !pair.hasRequest()) {
            return;
        }
        
        String host = pair.getHost();
        String url = pair.getUrl();
        int port = pair.getPort();
        boolean useHttps = pair.isHttps();
        
        String fullUrl;
        if (port == 80 || port == 443 || port <= 0) {
            fullUrl = (useHttps ? "https://" : "http://") + host + url;
        } else {
            fullUrl = (useHttps ? "https://" : "http://") + host + ":" + port + url;
        }
        
        copyToClipboard(fullUrl);
    }
    
    /**
     * Build HttpRequest from MatchedHttpPair.
     */
    private HttpRequest buildHttpRequest(MatchedHttpPair pair) {
        CapturedEvent request = pair.getRequest();
        if (request == null || request.getPayload() == null) {
            return null;
        }
        
        String host = pair.getHost();
        
        // Validate host
        if (host == null || host.isEmpty() || host.equals("0.0.0.0") || host.equals("-") || host.equals("(unknown)")) {
            logging.logToError("Cannot build request: invalid host '" + host + "'");
            return null;
        }
        
        // Get port - default to 443 for common HTTPS hosts
        int port = pair.getPort();
        if (port <= 0) {
            port = 443; // Default to HTTPS
        }
        boolean useHttps = pair.isHttps();
        
        try {
            // Create HttpService
            HttpService httpService = HttpService.httpService(pair.getServiceHost(), port, useHttps);
            
            // Create HttpRequest with service and raw request string
            return HttpRequest.httpRequest(httpService, ByteArray.byteArray(request.getPayload()));
        } catch (Exception e) {
            logging.logToError("Error building HttpRequest: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Copy text to system clipboard.
     */
    private void copyToClipboard(String text) {
        java.awt.datatransfer.StringSelection selection = 
                new java.awt.datatransfer.StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }
    
    /**
     * ContextMenuItemsProvider implementation for Burp's built-in context menu.
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // We only provide context menu in our own table, not in Burp's UI
        return new ArrayList<>();
    }
}
