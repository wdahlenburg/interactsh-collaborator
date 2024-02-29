package burp.listeners;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.TimeUnit;

import interactsh.Client;

public class InteractshListener {
    private Thread poller;
    private boolean running = true;
    private Client client;

    public InteractshListener() {
        this.poller = new Thread(new Runnable() {
            public void run() {
                client = new Client();
                try {
                    if(client.register()){
                        while (running == true) {
                            client.poll();
    
                            try {
                                TimeUnit.SECONDS.sleep(burp.BurpExtender.getPollTime());
                            } catch (InterruptedException ie) {
                                // Ignore interrupt (re evaluate running and polling)
                            }
                        }
                    } else {
                        burp.BurpExtender.api.logging().logToError("Unable to register interactsh client");
                    }


                } catch (Exception ex) {
                    burp.BurpExtender.api.logging().logToError(ex.getMessage());
                }

                if (client.isRegistered()){
                    client.deregister();
                }
            }
        });
        this.poller.start();
    }

    public void close() {
        this.running = false;
        this.poller.interrupt();
        try {
            this.poller.join();
        } catch (InterruptedException ex) {
            burp.BurpExtender.api.logging().logToError(ex.getMessage());
        }
    }

    public void pollNowAll() {
        this.poller.interrupt();
    }

    public void generateCollaborator() {
        String interactDomain = client.getInteractDomain();
        burp.BurpExtender.api.logging().logToOutput("New domain is: " + interactDomain);
        StringSelection stringSelection = new StringSelection(interactDomain);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
    }
}