package burp.gui;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class PollTimeListener implements DocumentListener {
    @Override
    public void insertUpdate(DocumentEvent documentEvent) {
        changedUpdate(documentEvent);
    }

    @Override
    public void removeUpdate(DocumentEvent documentEvent) {
        changedUpdate(documentEvent);
    }

    @Override
    public void changedUpdate(DocumentEvent documentEvent) {
        burp.BurpExtender.updatePollTime(burp.BurpExtender.getPollTime());
    }
}
