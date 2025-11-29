package sessionGuard.gui.main;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.border.EmptyBorder;
import sessionGuard.controller.ContextMenuController;

import burp.BurpExtender;

public class MainPanel extends JPanel {

	private static final long serialVersionUID = -8438576029794021570L;
	private final ConfigurationPanel configurationPanel;
	private final JSplitPane splitPane;
	private final CenterPanel centerPanel;
	private final SessionMonitorPanel sessionMonitorPanel;
	private final JTabbedPane mainTabs;

	public MainPanel() {
		setLayout(new BorderLayout(10, 10));
		setBorder(new EmptyBorder(5, 5, 5, 5));
		centerPanel = new CenterPanel(this);
		configurationPanel = new ConfigurationPanel(this);
		JScrollPane scrollPane = new JScrollPane(configurationPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(20);
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, centerPanel);
		splitPane.setDividerSize(6);
		splitPane.setContinuousLayout(true);
		splitPane.setOneTouchExpandable(true);
		splitPane.setResizeWeight(0.65d);
		splitPane.setDividerLocation(0.62d);
		sessionMonitorPanel = new SessionMonitorPanel(this);
		mainTabs = new JTabbedPane();
		mainTabs.addTab("Analyzer", splitPane);
		mainTabs.addTab("Session Monitor", sessionMonitorPanel);
		add(mainTabs, BorderLayout.CENTER);
		BurpExtender.callbacks.registerContextMenuFactory(new ContextMenuController(configurationPanel));
		configurationPanel.loadAutoStoredData();
	}
	
	public void updateDividerLocation() {
		double currentSize = getSize().getHeight();
		if(currentSize <= 0) {
			return;
		}
		double configPanelHeight = configurationPanel.getPreferredSize().getHeight();
		double relation = configPanelHeight / currentSize;
		relation = Math.max(0.35d, Math.min(relation, 0.85d));
		splitPane.setDividerLocation(relation);
		splitPane.setResizeWeight(relation);
	}
	
	public CenterPanel getCenterPanel() {
		return centerPanel;
	}
	
	public ConfigurationPanel getConfigurationPanel() {
		return configurationPanel;
	}

	public SessionMonitorPanel getSessionMonitorPanel() {
		return sessionMonitorPanel;
	}
	
	public void showSessionMonitorTab() {
		mainTabs.setSelectedComponent(sessionMonitorPanel);
		sessionMonitorPanel.showMacroManager();
	}
}