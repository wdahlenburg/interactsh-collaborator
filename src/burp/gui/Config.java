package burp.gui;

import burp.api.montoya.persistence.Preferences;

public class Config {
    public static void generateConfig() {
        Preferences preferences = burp.BurpExtender.api.persistence().preferences();

        String server = preferences.getString("interactsh-server");
        String port = preferences.getString("interactsh-port");

        if ((server == null || server.isEmpty()) ||
                (port == null || port.isEmpty()) ||
                !preferences.stringKeys().contains("interactsh-authorization") ||
                !preferences.stringKeys().contains("interactsh-uses-tls")) {
            preferences.setString("interactsh-server", "oast.pro");
            preferences.setString("interactsh-port", "443");
            preferences.setString("interactsh-authorization", "");
            preferences.setString("interactsh-poll-time", "60");
            preferences.setString("interactsh-uses-tls", Boolean.toString(true));
        }
    }

    public static void loadConfig() {
        Preferences preferences = burp.BurpExtender.api.persistence().preferences();
        String server = preferences.getString("interactsh-server");
        String port = preferences.getString("interactsh-port");
        String tls = preferences.getString("interactsh-uses-tls");
        String authorization = preferences.getString("interactsh-authorization");
        String pollinterval = preferences.getString("interactsh-poll-time");

        // Update each of the text boxes on the Configuration pane
        burp.BurpExtender.tab.setServerText(server);
        burp.BurpExtender.tab.setPortText(port);
        burp.BurpExtender.tab.setAuthText(authorization);
        burp.BurpExtender.tab.setPollText(pollinterval);
        burp.BurpExtender.tab.setTlsBox(Boolean.parseBoolean(tls));
    }

    public static void updateConfig() {
        Preferences preferences = burp.BurpExtender.api.persistence().preferences();

        // Read each of the text boxes on the Configuration pane
        String server = burp.BurpExtender.tab.getServerText();
        String port = burp.BurpExtender.tab.getPortText();
        String authorization = burp.BurpExtender.tab.getAuthText();
        String pollinterval = burp.BurpExtender.tab.getPollText();
        String tls = burp.BurpExtender.tab.getTlsBox();

        preferences.setString("interactsh-server", server);
        preferences.setString("interactsh-port", port);
        preferences.setString("interactsh-uses-tls", tls);
        preferences.setString("interactsh-poll-time", pollinterval);
        preferences.setString("interactsh-authorization", authorization);
    }

    public static String getHost() {
        return burp.BurpExtender.api.persistence().preferences().getString("interactsh-server");
    }

    public static String getPort() {
        return burp.BurpExtender.api.persistence().preferences().getString("interactsh-port");
    }

    public static boolean getScheme() {
        return Boolean.parseBoolean(burp.BurpExtender.api.persistence().preferences().getString("interactsh-uses-tls"));
    }

    public static String getAuth() {
        return burp.BurpExtender.api.persistence().preferences().getString("interactsh-authorization");
    }

    public static String getPollInterval() {
        return burp.BurpExtender.api.persistence().preferences().getString("interactsh-poll-time");
    }
}


