package burp.listeners;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import javax.swing.JOptionPane;

import burp.BurpExtender;
import interactsh.Client;

public class InteractshListener implements ActionListener {
    public ArrayList<Thread> pollers = new ArrayList<Thread>();
    public boolean running = true;
    public InteractshListener() {}
    @Override
    public void actionPerformed(ActionEvent e) {
          BurpExtender.getCallbacks().printOutput("Generating new Interactsh client");
          Client c = new Client();
          try {
              c.generateKeys();

              Thread polling = new Thread(new Runnable() {
                  public void run() {
                      try {
                          if (c.registerClient()) {
                              burp.BurpExtender.addClient(c);
                              while (running == true) {
                                  if (!c.poll()){
                                      return;
                                  }
                                  TimeUnit.SECONDS.sleep(burp.BurpExtender.pollTime);
                              }
                          } else {
                              JOptionPane.showMessageDialog(null, "Error registering client\n\nCheck configuration and/or extension proxy logs");
                              BurpExtender.getCallbacks().printOutput("Error registering client");
                          }
                      } catch (Exception ex) {
                          // Nothing to do here.
                      }
                  }
              });
              pollers.add(polling);
              polling.start();

              TimeUnit.SECONDS.sleep(1);
              // Set clipboard with new interactsh domain
              String domain = c.getInteractDomain();
              BurpExtender.getCallbacks().printOutput("New domain is: " + domain);
              StringSelection stringSelection = new StringSelection(domain);
              Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
          } catch (Exception ex){
              BurpExtender.getCallbacks().printOutput(ex.getMessage());
          }
    }
}