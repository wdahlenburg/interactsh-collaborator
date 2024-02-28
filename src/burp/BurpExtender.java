package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.gui.Config;
import burp.listeners.InteractshListener;
import burp.listeners.PollTimeListener;
import interactsh.InteractEntry;
import layout.SpringUtilities;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    public static MontoyaApi api;
    public static int pollTime = 60;
    public static InteractshTab tab;
    private InteractshListener listener;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.listener = new InteractshListener();

        api.extension().setName("Interactsh Collaborator");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(this);

        api.logging().logToOutput("Starting Interactsh Collaborator!");

        burp.gui.Config.generateConfig();
        tab = new InteractshTab(api, listener);
        burp.gui.Config.loadConfig();

        api.userInterface().registerSuiteTab("Interactsh", tab);
    }

    @Override
    public void extensionUnloaded() {
        if (listener != null) {
            // Get all threads and stop them.
            listener.running = false;
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
            }

            listener.pollNowAll();
            listener.cleanup();
        }
        api.logging().logToOutput("Thanks for collaborating!");
    }

    public static int getPollTime() {
        try {
            return Integer.parseInt(tab.getPollField().getText());
        } catch (Exception ex) {
        }
        return 60;
    }

    public static void updatePollTime(int poll) {
        pollTime = poll;
    }

    public static void addToTable(InteractEntry i) {
        tab.addToTable(i);
    }

    //
    // implement ContextMenuItemsProvider
    //

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<Component>();
        JMenuItem item = new JMenuItem("Generate Interactsh url");
        item.addActionListener(e -> listener.generateCollaborator());
        menuList.add(item);

        return menuList;
    }

    public class InteractshTab extends JComponent {
        private JTabbedPane mainPane;
        private JSplitPane splitPane;
        private JScrollPane scrollPane;
        private JSplitPane tableSplitPane;
        private JPanel resultsPanel;
        private JTextField pollField;
        private Table logTable;
        private static JTextField serverText;
        private static JTextField portText;
        private static JTextField authText;
        private static JTextField pollText;
        private static JCheckBox tlsBox;
        private List<InteractEntry> log = new ArrayList<InteractEntry>();
        private InteractshListener listener;

        public InteractshTab(MontoyaApi api, InteractshListener listener) {
            this.listener = listener;

            setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

            mainPane = new JTabbedPane();
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            mainPane.addTab("Logs", splitPane);

            resultsPanel = new JPanel();
            tableSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            logTable = new Table(new LogTable());
            scrollPane = new JScrollPane(logTable);

            tableSplitPane.setTopComponent(scrollPane);
            tableSplitPane.setBottomComponent(resultsPanel);
            splitPane.setBottomComponent(tableSplitPane);

            JPanel panel = new JPanel();
            JButton CollaboratorButton = new JButton("Generate Interactsh url");
            JButton RefreshButton = new JButton("Refresh");

            JLabel pollLabel = new JLabel("Poll Time: ");
            pollField = new JTextField(Config.getPollInterval(), 4);
            pollField.getDocument().addDocumentListener(new PollTimeListener());

            CollaboratorButton.addActionListener(e -> this.listener.generateCollaborator());
            RefreshButton.addActionListener(e -> listener.pollNowAll());
            panel.add(CollaboratorButton);
            panel.add(pollLabel);
            panel.add(pollField);
            panel.add(RefreshButton);
            splitPane.setTopComponent(panel);

            // Configuration pane
            JPanel configPanel = new JPanel();
            configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));
            JPanel subConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            mainPane.addTab("Configuration", configPanel);
            configPanel.add(subConfigPanel);
            JPanel innerConfig = new JPanel();
            subConfigPanel.setMaximumSize(new Dimension(configPanel.getMaximumSize().width, 250));
            innerConfig.setLayout(new SpringLayout());
            subConfigPanel.add(innerConfig);

            serverText = new JTextField("oast.pro", 20);
            portText = new JTextField("443", 20);
            authText = new JTextField("", 20);
            pollText = new JTextField("60", 20);
            tlsBox = new JCheckBox("", true);

            JLabel server = new JLabel("Server: ");
            innerConfig.add(server);
            server.setLabelFor(serverText);
            innerConfig.add(serverText);

            JLabel port = new JLabel("Port: ");
            innerConfig.add(port);
            port.setLabelFor(portText);
            innerConfig.add(portText);

            JLabel auth = new JLabel("Authorization: ");
            innerConfig.add(auth);
            auth.setLabelFor(authText);
            innerConfig.add(authText);

            JLabel poll = new JLabel("Poll Interval (sec): ");
            innerConfig.add(poll);
            poll.setLabelFor(pollText);
            innerConfig.add(pollText);

            JLabel tls = new JLabel("TLS: ");
            innerConfig.add(tls);
            tls.setLabelFor(tlsBox);
            innerConfig.add(tlsBox);

            JButton updateConfigButton = new JButton("Update Settings");
            updateConfigButton.addActionListener(e -> burp.gui.Config.updateConfig());
            innerConfig.add(updateConfigButton);

            // Add a blank panel so that SpringUtilities can make a well shaped grid
            innerConfig.add(new JPanel());

            SpringUtilities.makeCompactGrid(innerConfig,
                    6, 2, // rows, cols
                    6, 6, // initX, initY
                    6, 6); // xPad, yPad

            JPanel documentationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel help = new JLabel(
                    "Check out https://github.com/projectdiscovery/interactsh for an up to date list of public Interactsh servers",
                    SwingConstants.LEFT);
            documentationPanel.setAlignmentY(Component.TOP_ALIGNMENT);
            documentationPanel.add(help);
            configPanel.add(documentationPanel);

            add(mainPane);
        }

        public static String getServerText() {
            return serverText.getText();
        }

        public static void setServerText(String t) {
            serverText.setText(t);
        }

        public static String getPortText() {
            return portText.getText();
        }

        public static void setPortText(String text) {
            portText.setText(text);
        }

        public static String getAuthText() {
            return authText.getText();
        }

        public static String getPollText() {
            return pollText.getText();
        }

        public static void setAuthText(String text) {
            authText.setText(text);
        }

        public static void setPollText(String text) {
            pollText.setText(text);
        }

        public static String getTlsBox() {
            return Boolean.toString(tlsBox.isSelected());
        }

        public static void setTlsBox(boolean value) {
            tlsBox.setSelected(value);
        }

        public JTextField getPollField() {
            return pollField;
        }

        public void addToTable(InteractEntry i) {
            log.add(i);
            logTable.revalidate();
        }

        //
        // extend JTable to handle cell selection
        //

        private class Table extends JTable {
            public TableModel tableModel;

            public Table(TableModel tableModel) {
                super(tableModel);
                this.tableModel = tableModel;
            }

            @Override
            public void changeSelection(int row, int col, boolean toggle, boolean extend) {
                // show the log entry for the selected row
                InteractEntry ie = log.get(row);

                resultsPanel.removeAll(); // Refresh pane
                resultsPanel.setLayout(new BorderLayout()); // give your JPanel a BorderLayout

                JTextArea text = new JTextArea(ie.details);
                JScrollPane scroll = new JScrollPane(text); // place the JTextArea in a scroll pane
                resultsPanel.add(scroll, BorderLayout.CENTER); // add the JScrollPane to the panel
                tableSplitPane.revalidate();

                super.changeSelection(row, col, toggle, extend);
            }
        }

        //
        // implement AbstractTableModel
        //

        private class LogTable extends AbstractTableModel {

            @Override
            public int getRowCount() {
                return log.size();
            }

            @Override
            public int getColumnCount() {
                return 4;
            }

            @Override
            public String getColumnName(int columnIndex) {
                switch (columnIndex) {
                    case 0:
                        return "Entry";
                    case 1:
                        return "Type";
                    case 2:
                        return "Address";
                    case 3:
                        return "Time";
                    default:
                        return "";
                }
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return String.class;
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex) {
                InteractEntry ie = log.get(rowIndex);

                switch (columnIndex) {
                    case 0:
                        return ie.uid;
                    case 1:
                        return ie.protocol;
                    case 2:
                        return ie.address;
                    case 3:
                        return ie.timestamp;
                    default:
                        return "";
                }
            }
        }
    }
}