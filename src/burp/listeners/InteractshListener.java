package burp.listeners;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import interactsh.Client;

public class InteractshListener {
    public Thread poller;
    public boolean running = true;
    private Client client;

    public InteractshListener() {

        try {
            client = new Client();
            client.register();
        } catch (NoSuchAlgorithmException ex) {
            burp.BurpExtender.api.logging().logToError(ex.getMessage());
        }
        this.poller = new Thread(new Runnable() {
            public void run() {
                try {
                    while (running == true) {
                        client.poll();

                        try {
                            TimeUnit.SECONDS.sleep(burp.BurpExtender.getPollTime());
                        } catch (InterruptedException ie) {
                            // Ignore interrupt (re evaluate running and polling)
                        }
                    }
                } catch (Exception ex) {
                    burp.BurpExtender.api.logging().logToError(ex.getMessage());
                }
            }
        });
        this.poller.start();
    }

    public void pollNowAll() {
        this.poller.interrupt();
    }

    public void generateCollaborator() {
        burp.BurpExtender.api.logging().logToOutput("Generating new Interactsh client");

        String interactDomain = client.getInteractDomain();
        burp.BurpExtender.api.logging().logToOutput("New domain is: " + interactDomain);
        StringSelection stringSelection = new StringSelection(interactDomain);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
    }

    public void cleanup() {
        this.client.deregister();
    }

}