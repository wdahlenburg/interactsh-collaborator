package burp.gui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

public class Config {
    public static void generateConfig(){
        IBurpExtenderCallbacks callbacks = burp.BurpExtender.getCallbacks();

        String server = callbacks.loadExtensionSetting("interactsh-server");
        String port = callbacks.loadExtensionSetting("interactsh-port");

        if ((server == null || server.isEmpty()) ||
                (port == null || port.isEmpty())){
            callbacks.saveExtensionSetting("interactsh-server", "interact.sh");
            callbacks.saveExtensionSetting("interactsh-port", "443");
            callbacks.saveExtensionSetting("interactsh-uses-tls", Boolean.toString(true));
        }
    }

    public static void loadConfig(){
        IBurpExtenderCallbacks callbacks = burp.BurpExtender.getCallbacks();
        String server = callbacks.loadExtensionSetting("interactsh-server");
        String port = callbacks.loadExtensionSetting("interactsh-port");
        boolean tls = Boolean.parseBoolean(callbacks.loadExtensionSetting("interactsh-uses-tls"));
        String authorization = callbacks.loadExtensionSetting("interactsh-authorization");

        // Update each of the text boxes on the Configuration pane
        burp.BurpExtender.serverText.setText(server);
        burp.BurpExtender.portText.setText(port);
        burp.BurpExtender.authText.setText(authorization);
        burp.BurpExtender.tlsBox.setSelected(tls);
    }

    public static void updateConfig(){
        IBurpExtenderCallbacks callbacks = burp.BurpExtender.getCallbacks();

        // Read each of the text boxes on the Configuration pane
        String server = burp.BurpExtender.serverText.getText();
        String port = burp.BurpExtender.portText.getText();
        String authorization = burp.BurpExtender.authText.getText();
        boolean tls = burp.BurpExtender.tlsBox.isSelected();

        callbacks.saveExtensionSetting("interactsh-server", server);
        callbacks.saveExtensionSetting("interactsh-port", port);
        callbacks.saveExtensionSetting("interactsh-uses-tls", Boolean.toString(tls));
        callbacks.saveExtensionSetting("interactsh-authorization", authorization);
    }

    public static String getHost(){
        return burp.BurpExtender.getCallbacks().loadExtensionSetting("interactsh-server");
    }

    public static String getPort(){
        return burp.BurpExtender.getCallbacks().loadExtensionSetting("interactsh-port");
    }

    public static boolean getScheme(){
        return Boolean.parseBoolean(burp.BurpExtender.getCallbacks().loadExtensionSetting("interactsh-uses-tls"));
    }

    public static String getAuth(){
        return burp.BurpExtender.getCallbacks().loadExtensionSetting("interactsh-authorization");
    }

    public static String getUrl(){
        String scheme = "https://";
        if(Boolean.parseBoolean(burp.BurpExtender.getCallbacks().loadExtensionSetting("interactsh-server")) ==  false){
            scheme = "http://";
        }

        String url = scheme + getHost();
        String port = getPort();
        if(!(port == "80" || port == "443")){
            url += ":" + port;
        }

        return url;
    }
}


