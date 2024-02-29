package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.gui.InteractshTab;
import interactsh.InteractEntry;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    public static MontoyaApi api;
    public static int pollTime = 60;
    public static InteractshTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        BurpExtender.api = api;

        api.extension().setName("Interactsh Collaborator");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(this);

        api.logging().logToOutput("Starting Interactsh Collaborator!");

        burp.gui.Config.generateConfig();
        BurpExtender.tab = new InteractshTab(api);
        burp.gui.Config.loadConfig();

        api.userInterface().registerSuiteTab("Interactsh", tab);
    }

    @Override
    public void extensionUnloaded() {
        BurpExtender.tab.cleanup();
        BurpExtender.api.logging().logToOutput("Thanks for collaborating!");
    }

    public static int getPollTime() {
        try {
            return Integer.parseInt(BurpExtender.tab.getPollField().getText());
        } catch (Exception ex) {
        }
        return 60;
    }

    public static void updatePollTime(int poll) {
        pollTime = poll;
    }

    public static void addToTable(InteractEntry i) {
        BurpExtender.tab.addToTable(i);
    }

    //
    // implement ContextMenuItemsProvider
    //

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<Component>();
        JMenuItem item = new JMenuItem("Generate Interactsh url");
        item.addActionListener(e -> BurpExtender.tab.getListener().generateCollaborator());
        menuList.add(item);

        return menuList;
    }
}