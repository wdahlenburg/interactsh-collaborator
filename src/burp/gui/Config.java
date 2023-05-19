package burp.gui;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

public class Config {
    public static void generateConfig() {
        burp.BurpExtender.api.persistence().extensionData().deleteString("interactsh-server");
        burp.BurpExtender.api.persistence().extensionData().setString("interactsh-server", "oast.pro");
        burp.BurpExtender.api.persistence().extensionData().deleteString("interactsh-port");
        burp.BurpExtender.api.persistence().extensionData().setString("interactsh-port", "443");
        burp.BurpExtender.api.persistence().extensionData().deleteBoolean("interactsh-uses-tls");
        burp.BurpExtender.api.persistence().extensionData().setBoolean("interactsh-uses-tls", true);
    }

    public static void loadConfig() {
        String server = burp.BurpExtender.api.persistence().extensionData().getString("interactsh-server");
        BurpExtender.api.logging().logToOutput("Server from config is: " + server);
        String port = burp.BurpExtender.api.persistence().extensionData().getString("interactsh-port");
        boolean tls = true;
        if (burp.BurpExtender.api.persistence().extensionData().getBoolean("interactsh-uses-tls") != null) {
            tls = burp.BurpExtender.api.persistence().extensionData().getBoolean("interactsh-uses-tls");
        }
        String authorization = burp.BurpExtender.api.persistence().extensionData().getString("interactsh-authorization");

        if ((server == null || server.isEmpty()) ||
                (port == null || port.isEmpty())) {
            BurpExtender.api.logging().logToOutput("Server is: " + server + "; Port is: " + port + "; Re-generating config");
            generateConfig();
            server = burp.BurpExtender.api.persistence().extensionData().getString("interactsh-server");
            port = burp.BurpExtender.api.persistence().extensionData().getString("interactsh-port");
            tls = burp.BurpExtender.api.persistence().extensionData().getBoolean("interactsh-uses-tls");
            authorization = null;
        }

        // Update each of the text boxes on the Configuration pane
        burp.BurpExtender.setServerText(server);
        burp.BurpExtender.setPortText(port);
        burp.BurpExtender.setAuthText(authorization);
        burp.BurpExtender.setTlsBox(tls);
    }

    public static void updateConfig() {
        // Read each of the text boxes on the Configuration pane
        String server = burp.BurpExtender.getServerText();
        String port = burp.BurpExtender.getPortText();
        String authorization = burp.BurpExtender.getAuthText();
        boolean tls = burp.BurpExtender.getTlsBox();

        BurpExtender.api.logging().logToOutput("Server is now: " + server);

        burp.BurpExtender.api.persistence().extensionData().deleteString("interactsh-server");
        burp.BurpExtender.api.persistence().extensionData().setString("interactsh-server", server);
        burp.BurpExtender.api.persistence().extensionData().deleteString("interactsh-port");
        burp.BurpExtender.api.persistence().extensionData().setString("interactsh-port", port);
        burp.BurpExtender.api.persistence().extensionData().deleteString("interactsh-authorization");
        burp.BurpExtender.api.persistence().extensionData().setString("interactsh-authorization", authorization);
        burp.BurpExtender.api.persistence().extensionData().deleteBoolean("interactsh-uses-tls");
        burp.BurpExtender.api.persistence().extensionData().setBoolean("interactsh-uses-tls", tls);


        BurpExtender.api.logging().logToOutput("Server is now: " + burp.BurpExtender.api.persistence().extensionData().getString("interactsh-server"));
    }

    public static String getHost() {
        if (burp.BurpExtender.api.persistence().extensionData().getString("interactsh-server") != null) {
            return burp.BurpExtender.api.persistence().extensionData().getString("interactsh-server");
        }
        return burp.BurpExtender.getServerText();
    }

    public static String getPort() {
        if (burp.BurpExtender.api.persistence().extensionData().getString("interactsh-port") != null) {
            return burp.BurpExtender.api.persistence().extensionData().getString("interactsh-port");
        }
        return burp.BurpExtender.getPortText();
    }

    public static boolean getScheme() {
        if (burp.BurpExtender.api.persistence().extensionData().getBoolean("interactsh-uses-tls") != null) {
            return burp.BurpExtender.api.persistence().extensionData().getBoolean("interactsh-uses-tls");
        }
        return burp.BurpExtender.getTlsBox();
    }

    public static String getAuth() {
        if (burp.BurpExtender.api.persistence().extensionData().getString("interactsh-authorization") != null) {
            return burp.BurpExtender.api.persistence().extensionData().getString("interactsh-authorization");
        }
        return burp.BurpExtender.getAuthText();
    }
}


