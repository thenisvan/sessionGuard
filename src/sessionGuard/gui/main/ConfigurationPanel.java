package sessionGuard.gui.main;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Scanner;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.JScrollPane;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.Box;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import sessionGuard.entities.AutoExtractLocation;
import sessionGuard.entities.FromToExtractLocation;
import sessionGuard.entities.MatchAndReplace;
import sessionGuard.entities.Session;
import sessionGuard.entities.SessionRenewalMacro;
import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.Token;
import sessionGuard.entities.TokenBuilder;
import sessionGuard.entities.TokenLocation;
import sessionGuard.filter.FileTypeFilter;
import sessionGuard.filter.InScopeFilter;
import sessionGuard.filter.MethodFilter;
import sessionGuard.filter.OnlyProxyFilter;
import sessionGuard.filter.PathFilter;
import sessionGuard.filter.QueryFilter;
import sessionGuard.filter.RequestFilter;
import sessionGuard.filter.StatusCodeFilter;
import sessionGuard.gui.dialog.SettingsDialog;
import sessionGuard.gui.entity.SessionPanel;
import sessionGuard.gui.entity.TokenPanel;
import sessionGuard.gui.listener.CloneSessionListener;
import sessionGuard.gui.listener.DeleteSessionListener;
import sessionGuard.gui.listener.NewSessionListener;
import sessionGuard.gui.listener.RenameSessionListener;
import sessionGuard.gui.util.HintCheckBox;
import sessionGuard.gui.util.SessionTabbedPane;
import sessionGuard.util.CurrentConfig;
import sessionGuard.util.DataStorageProvider;
import sessionGuard.util.GenericHelper;
import burp.BurpExtender;

public class ConfigurationPanel extends JPanel {

	private static final long serialVersionUID = -4278008236240529083L;
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final String ANALYZER_STOPPED_TEXT = "Stopped";
	private final String ANALYZER_STARTED_TEXT = "Running";
	private final String ANALYZER_PAUSED_TEXT = "<html><span style='color:orange; font-weight: bold'>&#x26AB;</span> Analyzer Paused</html>";
	private final String DROP_REQUEST_TEXT = "Drop Original Requests";
	private final String STOP_DROP_REQUEST_TEXT = "Stop Drop Requests";
	private final JButton startStopButton = new JButton();
	private final JButton pauseButton = new JButton();
	//private final JLabel pendingRequestsLabel = new JLabel("Pending Requests Queue: 0");
	private final JToggleButton dropOriginalButton = new JToggleButton(DROP_REQUEST_TEXT);
	private final JPanel filterPanel;
	private final LinkedHashMap<String, SessionPanel> sessionPanelMap = new LinkedHashMap<>();
	private final String PAUSE_TEXT = "\u23f8";
	private final String PLAY_TEXT = "\u25b6";
	private final SessionTabbedPane sessionTabbedPane = new SessionTabbedPane();
	boolean sessionListChanged = true;
	private final MainPanel mainPanel;

	public ConfigurationPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;	
		sessionTabbedPane.addNewSessionListener(new NewSessionListener() {
			@Override
			public void newSession() {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of Session");
				if (sessionName != null && isSessionNameValid(sessionName)) {
					createSession(sessionName);
				}
			}
		});
		
		sessionTabbedPane.addCloneSessionListener(new CloneSessionListener() {
			
			@Override
			public void cloneSession() {
				String newSessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of New Session");
				if (newSessionName != null && isSessionNameValid(newSessionName)) {
					int currentIndex = sessionTabbedPane.getSelectedIndex();
					String currentSessionName = sessionTabbedPane.getTitleAt(currentIndex);
					doCloneSession(newSessionName, sessionPanelMap.get(currentSessionName));
				}
			}
		});
		
		sessionTabbedPane.addRenameSessionListener(new RenameSessionListener() {
			@Override
			public void renameSession(String currentName) {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Rename Current Session:",
						currentName);
				if (sessionName != null && isSessionNameValid(sessionName)) {
					if (doModify()) {
						sessionTabbedPane.setTitleAt(getTabbedPaneIndexForTitle(currentName), sessionName);
						sessionPanelMap.put(sessionName, sessionPanelMap.get(currentName));
						sessionPanelMap.remove(currentName);
						sessionPanelMap.get(sessionName).setSessionName(sessionName);
					}
				}
			}
		});
		
		sessionTabbedPane.addDeleteSessionListener(new DeleteSessionListener() {		
			@Override
			public void deleteSession(String title) {
				if (doModify()) {
					sessionPanelMap.remove(title);
					sessionTabbedPane.remove(getTabbedPaneIndexForTitle(title));
					sessionTabbedPane.setSelectedIndex(0);
				}
			}
		});

		filterPanel = new JPanel();
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

		HintCheckBox onlyInScopeButton = new HintCheckBox("Only In Scope");
		onlyInScopeButton.setSelected(true);
		addFilter(new InScopeFilter(filterPanel.getComponentCount(), "Only In Scope requests are analyzed"),
				onlyInScopeButton, "");
		filterPanel.add(onlyInScopeButton);

		HintCheckBox onlyProxyButton = new HintCheckBox("Only Proxy Traffic");
		onlyProxyButton.setSelected(true);
		onlyProxyButton.setVisible(false); // Hidden
		addFilter(
				new OnlyProxyFilter(filterPanel.getComponentCount(),
						"Analyze only proxy traffic. Unselect to analyze repeater and proxy traffic"),
				onlyProxyButton, "");
		filterPanel.add(onlyProxyButton);

		HintCheckBox fileTypeFilterButton = new HintCheckBox("Exclude Filetypes");
		fileTypeFilterButton.setSelected(true);
		fileTypeFilterButton.setVisible(false); // Hidden
		addFilter(new FileTypeFilter(filterPanel.getComponentCount(), "Excludes every specified filetype"),
				fileTypeFilterButton, "Enter filetypes to filter. Comma separated.\r\neg: jpg, png, js");
		filterPanel.add(fileTypeFilterButton);

		HintCheckBox methodFilterButton = new HintCheckBox("Exclude HTTP Methods");
		methodFilterButton.setSelected(true);
		methodFilterButton.setVisible(false); // Hidden
		addFilter(new MethodFilter(filterPanel.getComponentCount(), "Excludes every specified http method"),
				methodFilterButton, "Enter HTTP methods to filter. Comma separated.\r\neg: OPTIONS, TRACE");
		filterPanel.add(methodFilterButton);

		HintCheckBox statusCodeFilterButton = new HintCheckBox("Exclude Status Codes");
		statusCodeFilterButton.setSelected(true);
		statusCodeFilterButton.setVisible(false); // Hidden
		addFilter(new StatusCodeFilter(filterPanel.getComponentCount(), "Excludes every specified status code"),
				statusCodeFilterButton, "Enter status codes to filter. Comma separated.\r\neg: 204, 304");
		filterPanel.add(statusCodeFilterButton);

		HintCheckBox pathFilterButton = new HintCheckBox("Exclude Paths");
		pathFilterButton.setSelected(false);
		pathFilterButton.setVisible(false); // Hidden
		addFilter(
				new PathFilter(filterPanel.getComponentCount(),
						"Excludes every path that contains one of the specified string literals"),
				pathFilterButton,
				"Enter String literals for paths to be excluded. Comma separated.\r\neg: log, libraries");
		filterPanel.add(pathFilterButton);

		HintCheckBox queryFilterButton = new HintCheckBox("Exclude Queries / Params");
		queryFilterButton.setSelected(false);
		queryFilterButton.setVisible(false); // Hidden
		addFilter(
				new QueryFilter(filterPanel.getComponentCount(),
						"Excludes every GET query that contains one of the specified string literals"),
				queryFilterButton,
				"Enter string literals for queries to be excluded. Comma separated.\r\neg: log, core");
		filterPanel.add(queryFilterButton);
		startStopButton.setText(ANALYZER_STOPPED_TEXT);
		startStopButton.setOpaque(true);
		startStopButton.setBackground(null); // Default background
		startStopButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					startStopButtonPressed();
				} catch (Exception ex) {
					ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStdout()));
				}

			}
		});

		pauseButton.setText(PAUSE_TEXT);
		pauseButton.setEnabled(false);
		pauseButton.setVisible(false); // Hidden
		pauseButton.addActionListener(e -> pauseButtonPressed());

		dropOriginalButton.addActionListener(e -> dropOriginalButtonPressed());
		dropOriginalButton.setEnabled(false);
		dropOriginalButton.setVisible(false); // Hidden
		
		JButton settingsButton = new JButton("Settings");
		settingsButton.addActionListener(e -> new SettingsDialog(this));
		settingsButton.setVisible(false); // Hidden

		setLayout(new BorderLayout(12, 12));
		setBorder(new EmptyBorder(10, 10, 10, 10));

		JPanel controlsPanel = new JPanel();
		controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
		controlsPanel.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Analyzer Control"), new EmptyBorder(8, 8, 8, 8)));

		startStopButton.setAlignmentX(Component.LEFT_ALIGNMENT);
		controlsPanel.add(startStopButton);

		// Hidden: pause, dropOriginal, settings buttons
		// JPanel toggleRow = new JPanel(new GridBagLayout());
		// GridBagConstraints toggleConstraints = new GridBagConstraints();
		// toggleConstraints.insets = new Insets(0, 0, 0, 10);
		// toggleConstraints.anchor = GridBagConstraints.WEST;
		// toggleRow.add(pauseButton, toggleConstraints);
		// toggleConstraints.gridx = 1;
		// toggleConstraints.insets = new Insets(0, 0, 0, 0);
		// toggleRow.add(dropOriginalButton, toggleConstraints);
		// toggleRow.setAlignmentX(Component.LEFT_ALIGNMENT);
		// controlsPanel.add(Box.createVerticalStrut(6));
		// controlsPanel.add(toggleRow);
		//
		// settingsButton.setAlignmentX(Component.LEFT_ALIGNMENT);
		// controlsPanel.add(Box.createVerticalStrut(6));
		// controlsPanel.add(settingsButton);

		JScrollPane filterScrollPane = new JScrollPane(filterPanel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		filterScrollPane.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Filters"), new EmptyBorder(5, 5, 5, 5)));
		filterScrollPane.setPreferredSize(new Dimension(260, 0));

		JPanel leftColumn = new JPanel(new BorderLayout(0, 12));
		leftColumn.add(controlsPanel, BorderLayout.NORTH);
		leftColumn.add(filterScrollPane, BorderLayout.CENTER);
		leftColumn.setBorder(new EmptyBorder(0, 0, 0, 0));
		leftColumn.setPreferredSize(new Dimension(280, 0));
		add(leftColumn, BorderLayout.WEST);

		sessionTabbedPane.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Sessions"), new EmptyBorder(3, 3, 3, 3)));
		add(sessionTabbedPane, BorderLayout.CENTER);
		
	}

	public void loadAutoStoredData() {
		try {
			String storedData = DataStorageProvider.loadSetup();
			if(storedData != null) {
				loadSetup(storedData);
				mainPanel.updateDividerLocation();
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printOutput("Can not restore saved Data. Error Message: " + e.getMessage());
		}
		if(sessionTabbedPane.getTabCount() == 1) {
			createSession("user1");
		}
		sessionTabbedPane.setSelectedIndex(0);
	}
	
	public void saveSetup() {
		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File("Auth_Analyzer_Setup.json"));
		int status = chooser.showSaveDialog(this);
		if (status == JFileChooser.APPROVE_OPTION) {
			File file = chooser.getSelectedFile();
			if (!file.getName().endsWith(".json")) {
				String newFileName;
				if (file.getName().lastIndexOf(".") != -1) {
					int index = file.getAbsolutePath().lastIndexOf(".");
					newFileName = file.getAbsolutePath().substring(0, index);
				} else {
					newFileName = file.getAbsolutePath();
				}
				newFileName = newFileName + ".json";
				file = new File(newFileName);
			}
			try {
				FileWriter writer = new FileWriter(file);
				createSessionObjects(false);
				writer.write(DataStorageProvider.getSetupAsJsonString());
				writer.close();
				JOptionPane.showMessageDialog(this, "Successfully saved to\n" + file.getAbsolutePath());
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Error. Can not write setup to JSON file. " + e.getMessage());
				JOptionPane.showMessageDialog(this, "Error.\nCan not write setup to JSON file.");
			}
		}
	}

	public void loadSetup() {
		if(doModify()) {
			JFileChooser chooser = new JFileChooser();
			int status = chooser.showOpenDialog(this);
			if (status == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if(selectedFile != null) {
					Scanner scanner;
					String jsonString = "";
					try {
						scanner = new Scanner(selectedFile);
						while (scanner.hasNextLine()) {
							jsonString += scanner.nextLine();
						}
						scanner.close();
						sessionTabbedPane.removeAll();
						loadSetup(jsonString);
						mainPanel.updateDividerLocation();
						JOptionPane.showMessageDialog(this, "Setup successfully loaded");
					} catch (Exception e) {
						BurpExtender.callbacks.printError("Error. Can not load setup from JSON file. " + e.getMessage());
						JOptionPane.showMessageDialog(this, "Error.\nCan not load setup from JSON file.");
					}
				}
			}
		}
	}
	
	public void refreshSessionMacroOptions() {
		for(SessionPanel panel : sessionPanelMap.values()) {
			panel.refreshMacroOptions();
		}
	}

	private void dropOriginalButtonPressed() {
		if (CurrentConfig.getCurrentConfig().isDropOriginal()) {
			setDropOriginalRequest(false);
		} else {
			setDropOriginalRequest(true);
		}
	}

	private void setDropOriginalRequest(boolean dropRequests) {
		if (dropRequests) {
			dropOriginalButton.setText(STOP_DROP_REQUEST_TEXT);
			dropOriginalButton.setSelected(true);
			CurrentConfig.getCurrentConfig().setDropOriginal(true);
		} else {
			dropOriginalButton.setText(DROP_REQUEST_TEXT);
			dropOriginalButton.setSelected(false);
			CurrentConfig.getCurrentConfig().setDropOriginal(false);
		}
	}

	private boolean isSessionNameValid(String sessionName) {
		if (sessionName != null && !sessionName.equals("") && !sessionPanelMap.containsKey(sessionName)
				&& !sessionName.equals("Original")) {
			return true;
		} else {
			JOptionPane.showMessageDialog(this, "The entered Session Name is invalid", "Session Name Invalid",
					JOptionPane.WARNING_MESSAGE);
			return false;
		}
	}

	private SessionPanel createSession(String sessionName) {
		if (doModify()) {
			SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
			sessionPanel.refreshMacroOptions();
			sessionTabbedPane.add(sessionName, sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 2);
			sessionPanelMap.put(sessionName, sessionPanel);
			return sessionPanel;
		} else {
			return null;
		}
	}

	private boolean doCloneSession(String newSessionName, SessionPanel sessionPanelToClone) {
		if (doModify()) {
			SessionPanel sessionPanel = new SessionPanel(newSessionName, mainPanel);
			sessionPanel.refreshMacroOptions();
			sessionPanel.setHeadersToReplaceText(sessionPanelToClone.getHeadersToReplaceText());
			sessionPanel.setHeadersToRemoveText(sessionPanelToClone.getHeadersToRemoveText());
			sessionPanel.setRemoveHeaders(sessionPanelToClone.isRemoveHeaders());
			sessionPanel.setFilterRequestsWithSameHeader(sessionPanelToClone.isFilterRequestsWithSameHeader());
			sessionPanel.setRestrictToScope(sessionPanelToClone.isRestrictToScope());
			sessionPanel.setRestrictToScopeText(sessionPanelToClone.getRestrictToScopeText());
			sessionPanel.setTestCors(sessionPanelToClone.isTestCors());
			sessionPanel.setMatchAndReplaceList(sessionPanelToClone.getMatchAndReplaceList());
			for (TokenPanel tokenPanel : sessionPanelToClone.getTokenPanelList()) {
				TokenPanel newTokenPanel = sessionPanel.addToken(tokenPanel.getTokenName());
				newTokenPanel.setTokenLocationSet(tokenPanel.getTokenLocationSet());
				newTokenPanel.setAutoExtractLocationSet(tokenPanel.getAutoExtractLocationSet());
				newTokenPanel.setFromToExtractLocationSet(tokenPanel.getFromToExtractLocationSet());
				newTokenPanel.setIsRemoveToken(tokenPanel.isRemoveToken());
				newTokenPanel.setAddTokenIfNotExists(tokenPanel.isAddTokenIfNotExists());
				newTokenPanel.setCaseSensitiveTokenName(tokenPanel.isCaseSensitiveTokenName());
				if (tokenPanel.isAutoExtract()) {
					newTokenPanel.setAutoExtractFieldName(tokenPanel.getAutoExtractFieldName());
				}
				if (tokenPanel.isStaticValue()) {
					newTokenPanel.setStaticTokenValue(tokenPanel.getStaticTokenValue());
				}
				if (tokenPanel.isFromToString()) {
					newTokenPanel.setFromToString(tokenPanel.getGrepFromString(), tokenPanel.getGrepToString());
				}
				if (tokenPanel.isPromptForInput()) {
					newTokenPanel.setPromptForInput();
				}
			}
			sessionTabbedPane.add(newSessionName, sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 2);
			sessionPanelMap.put(newSessionName, sessionPanel);
			return true;
		} else {
			return false;
		}
	}

	// Creates a new session if session name not already exists and set header to
	// replace text
	public SessionPanel createSession(String sessionName, String headerToReplace) {
		if (!sessionPanelMap.containsKey(sessionName)) {
			SessionPanel sessionPanel = createSession(sessionName);
			if (sessionPanel != null) {
				sessionPanel.setHeadersToReplaceText(headerToReplace);
				return sessionPanel;
			}
		}
		return null;
	}

	private boolean doModify() {
		if (config.getTableModel().getRowCount() > 0 && !sessionListChanged) {
			int selection = JOptionPane.showConfirmDialog(this,
					"You are going to modify your session setup." + "\nTable data will be lost.",
					"Change Session Setup", JOptionPane.OK_CANCEL_OPTION);
			if (selection == JOptionPane.YES_OPTION) {
				sessionListChanged = true;
				mainPanel.getCenterPanel().clearTable();
				return true;
			} else {
				return false;
			}
		} else {
			sessionListChanged = true;
			return true;
		}
	}

	public SessionPanel getSessionPanelByName(String name) {
		return sessionPanelMap.get(name);
	}

	public void setSelectedSession(String sessionName) {
		int index = getTabbedPaneIndexForTitle(sessionName);
		if(index != -1) {
			sessionTabbedPane.setSelectedIndex(index);
		}
	}
	
	private int getTabbedPaneIndexForTitle(String title) {
		for (int i = 0; i < sessionTabbedPane.getTabCount()-1; i++) {
			if (sessionTabbedPane.getTitleAt(i).equals(title)) {
				return i;
			}
		}
		return -1;
	}

	public ArrayList<String> getSessionNames() {
		ArrayList<String> sessionNames = new ArrayList<String>();
		for (int i = 0; i < sessionTabbedPane.getTabCount()-1; i++) {
			sessionNames.add(sessionTabbedPane.getTitleAt(i));
		}
		return sessionNames;
	}

	private void addFilter(RequestFilter filter, HintCheckBox onOffButton, String inputDialogText) {
		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
		onOffButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (onOffButton.isSelected() && filter.hasStringLiterals()) {
					String[] inputArray = getInputArray(onOffButton, inputDialogText,
							GenericHelper.getArrayAsString(filter.getFilterStringLiterals()));
					if (inputArray != null) {
						filter.setFilterStringLiterals(inputArray);
					}
				}
			}
		});
	}

	public void startStopButtonPressed() {
		if (sessionPanelMap.size() == 0) {
			JOptionPane.showMessageDialog(this, "No Session Created");
		} else {
			if (config.isRunning() || pauseButton.getText().equals(PLAY_TEXT)) {
				for (String session : sessionPanelMap.keySet()) {
					sessionPanelMap.get(session).setStopped();
				}
				sessionTabbedPane.setModifEnabled(true);
				pauseButton.setText(PAUSE_TEXT);
				pauseButton.setEnabled(false);
				dropOriginalButton.setEnabled(false);
				setDropOriginalRequest(false);
				config.setRunning(false);
				startStopButton.setText(ANALYZER_STOPPED_TEXT);
				startStopButton.setBackground(null); // Reset to default
			} else {
				// Validate all defined Tokens first
				boolean success = true;
				for (String session : sessionPanelMap.keySet()) {
					SessionPanel sessionPanel = sessionPanelMap.get(session);
					if (!sessionPanel.tokensValid() || !sessionPanel.isHeaderValid() || !sessionPanel.isScopeValid()) {
						success = false;
						setSelectedSession(session);
						break;
					}
				}
				if (success) {
					createSessionObjects(true);
					// Auto Store
					try {
						DataStorageProvider.saveSetup();
					} catch (Exception e) {
						BurpExtender.callbacks.printOutput("Can not store setup. Error Message: " + e.getMessage());
					}
					
					for (RequestFilter filter : config.getRequestFilterList()) {
						filter.resetFilteredAmount();
					}

					if(sessionListChanged) {
						mainPanel.getCenterPanel().initCenterPanel();
					}
					sessionTabbedPane.setModifEnabled(false);
					pauseButton.setEnabled(true);
					dropOriginalButton.setEnabled(true);
					config.setRunning(true);
					startStopButton.setText(ANALYZER_STARTED_TEXT);
					startStopButton.setBackground(java.awt.Color.RED);
					sessionListChanged = false;
				}
			}
			mainPanel.updateDividerLocation();
		}
	}
	
	public void createSessionObjects(boolean setRunning) {
		if(sessionPanelMap.size() != config.getSessions().size()) {
			sessionListChanged = true;
		}
		for (String session : sessionPanelMap.keySet()) {
			if(config.getSessionByName(session) == null) {
				sessionListChanged = true;
				break;
			}
		}
		if (sessionListChanged) {
			config.clearSessionList();
		}
		for (String session : sessionPanelMap.keySet()) {
			SessionPanel sessionPanel = sessionPanelMap.get(session);
			ArrayList<Token> tokenList = new ArrayList<Token>();
			for (TokenPanel tokenPanel : sessionPanel.getTokenPanelList()) {
				Token token = new TokenBuilder()
						.setName(tokenPanel.getTokenName())
						.setTokenLocationSet(tokenPanel.getTokenLocationSet())
						.setAutoExtractLocationSet(tokenPanel.getAutoExtractLocationSet())
						.setFromToExtractLocationSet(tokenPanel.getFromToExtractLocationSet())
						.setValue(tokenPanel.getStaticTokenValue())
						.setExtractName(tokenPanel.getAutoExtractFieldName())
						.setGrepFromString(tokenPanel.getGrepFromString())
						.setGrepToString(tokenPanel.getGrepToString())
						.setIsRemove(tokenPanel.isRemoveToken())
						.setIsAutoExtract(tokenPanel.isAutoExtract())
						.setIsStaticValue(tokenPanel.isStaticValue())
						.setIsFromToString(tokenPanel.isFromToString())
						.setIsPromptForInput(tokenPanel.isPromptForInput())
						.setIsCaseSensitiveTokenName(tokenPanel.isCaseSensitiveTokenName())
						.setIsAddIfNotExists(tokenPanel.isAddTokenIfNotExists())
						.setIsUrlEncoded(tokenPanel.isUrlEncoded())
						.setAliases(tokenPanel.getAliases())
						.build();
				tokenList.add(token);
			}
			Session newSession = null;
			if (sessionListChanged) {
				newSession = new Session(session, sessionPanel.getHeadersToReplaceText(), sessionPanel.isRemoveHeaders(),
						sessionPanel.getHeadersToRemoveText(), sessionPanel.isFilterRequestsWithSameHeader(), sessionPanel.isRestrictToScope(),
						sessionPanel.getScopeUrl(), sessionPanel.isTestCors(), tokenList, sessionPanel.getMatchAndReplaceList(), sessionPanel.getStatusPanel());
				newSession.setValidationConfig(sessionPanel.getSessionValidationConfig());
				config.addSession(newSession);
			} else {
				newSession = config.getSessionByName(session);
				newSession.setHeadersToReplace(sessionPanel.getHeadersToReplaceText());
				newSession.setRemoveHeaders(sessionPanel.isRemoveHeaders());
				newSession.setHeadersToRemove(sessionPanel.getHeadersToRemoveText());
				newSession.setFilterRequestsWithSameHeader(sessionPanel.isFilterRequestsWithSameHeader());
				newSession.setRestrictToScope(sessionPanel.isRestrictToScope());
				newSession.setScopeUrl(sessionPanel.getScopeUrl());
				newSession.setTestCors(sessionPanel.isTestCors());
				newSession.setMatchAndReplaceList(sessionPanel.getMatchAndReplaceList());
				newSession.setValidationConfig(sessionPanel.getSessionValidationConfig());
				for (Token newToken : tokenList) {
					for (Token oldToken : newSession.getTokens()) {
						if (newToken.getName().equals(oldToken.getName())) {
							if(newToken.isAutoExtract() && oldToken.isAutoExtract() ||
								newToken.isFromToString() && oldToken.isFromToString()) {
									newToken.setValue(oldToken.getValue());
									newToken.setRequestResponse(oldToken.getRequestResponse());
								}
						}
					}
				}
				newSession.setTokens(tokenList);
			}
			if(setRunning) {
				sessionPanel.setRunning();
				sessionPanel.getStatusPanel().init(newSession);
			}
			else {
				sessionPanel.getStatusPanel().updateValidationStatus(newSession);
			}
		}
		mainPanel.getSessionMonitorPanel().refreshSessions();
	}

	private void loadSetup(String jsonString) {
		sessionPanelMap.clear();
		sessionTabbedPane.removeAll();
		JsonObject root = JsonParser.parseString(jsonString).getAsJsonObject();
		
		// Load Macros first so session dropdowns have data
		ArrayList<SessionRenewalMacro> macros = new ArrayList<>();
		if(root.get("renewalMacros") != null && root.get("renewalMacros").isJsonArray()) {
			Type macroType = new TypeToken<ArrayList<SessionRenewalMacro>>(){}.getType();
			macros = new Gson().fromJson(root.get("renewalMacros"), macroType);
		}
		config.setRenewalMacros(macros);
		
		// Load Sessions
		JsonArray storedSessionsArray = root.get("sessions").getAsJsonArray();
		for (JsonElement sessionEl : storedSessionsArray) {
			JsonObject sessionObject = sessionEl.getAsJsonObject();
			String sessionName = sessionObject.get("name").getAsString();
			SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
			sessionPanel.setHeadersToReplaceText(sessionObject.get("headersToReplace").getAsString());
			sessionPanel
					.setFilterRequestsWithSameHeader(sessionObject.get("filterRequestsWithSameHeader").getAsBoolean());
			if(sessionObject.get("removeHeaders") != null) {
				sessionPanel.setRemoveHeaders(sessionObject.get("removeHeaders").getAsBoolean());
			}
			if(sessionObject.get("headersToRemove") != null) {
				sessionPanel.setHeadersToRemoveText(sessionObject.get("headersToRemove").getAsString());
			}
			if (sessionObject.get("restrictToScope") != null) {
				sessionPanel.setRestrictToScope(sessionObject.get("restrictToScope").getAsBoolean());
			}
			if (sessionObject.get("scopeUrl") != null) {
				sessionPanel.setRestrictToScopeText(sessionObject.get("scopeUrl").getAsString());
			}
			if (sessionObject.get("testCors") != null) {
				sessionPanel.setTestCors(sessionObject.get("testCors").getAsBoolean());
			}
			if(sessionObject.get("matchAndReplaceList") != null) {
				JsonArray matchAndReplaceArray = sessionObject.get("matchAndReplaceList").getAsJsonArray();
				ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
				for (JsonElement matchAndReplaceElement : matchAndReplaceArray) {
					JsonObject matchAndReplaceObject = matchAndReplaceElement.getAsJsonObject();
					if(matchAndReplaceObject.get("match") != null && matchAndReplaceObject.get("replace") != null) {
						matchAndReplaceList.add(new MatchAndReplace(matchAndReplaceObject.get("match").getAsString(), 
								matchAndReplaceObject.get("replace").getAsString()));
					}
				}
				sessionPanel.setMatchAndReplaceList(matchAndReplaceList);
			}
			JsonArray tokenArray = sessionObject.get("tokens").getAsJsonArray();
			for (JsonElement tokenElement : tokenArray) {
				JsonObject tokenObject = tokenElement.getAsJsonObject();
				// create new token panel for each token
				TokenPanel tokenPanel = sessionPanel.addToken(tokenObject.get("name").getAsString());
				if(tokenObject.get("tokenLocationSet") != null) {
					Type type = new TypeToken<EnumSet<TokenLocation>>(){}.getType();
					EnumSet<TokenLocation> tokenLocationSet =  new Gson().fromJson(tokenObject.get("tokenLocationSet"), type);
					tokenPanel.setTokenLocationSet(tokenLocationSet);
				}
				if(tokenObject.get("autoExtractLocationSet") != null) {
					Type type = new TypeToken<EnumSet<AutoExtractLocation>>(){}.getType();
					EnumSet<AutoExtractLocation> autoExtractLocationSet =  new Gson().fromJson(tokenObject.get("autoExtractLocationSet"), type);
					tokenPanel.setAutoExtractLocationSet(autoExtractLocationSet);
				}
				if(tokenObject.get("fromToExtractLocationSet") != null) {
					Type type = new TypeToken<EnumSet<FromToExtractLocation>>(){}.getType();
					EnumSet<FromToExtractLocation> fromToExtractLocationSet =  new Gson().fromJson(tokenObject.get("fromToExtractLocationSet"), type);
					tokenPanel.setFromToExtractLocationSet(fromToExtractLocationSet);
				}
				if(tokenObject.get("addIfNotExists") != null) {
					tokenPanel.setAddTokenIfNotExists(tokenObject.get("addIfNotExists").getAsBoolean());
				}
				if(tokenObject.get("urlEncoded") != null) {
					tokenPanel.setUrlEncoded(tokenObject.get("urlEncoded").getAsBoolean());
				}
				if(tokenObject.get("caseSensitiveTokenName") != null) {
					tokenPanel.setCaseSensitiveTokenName(tokenObject.get("caseSensitiveTokenName").getAsBoolean());
				}
				tokenPanel.setIsRemoveToken(tokenObject.get("remove").getAsBoolean());
				tokenPanel.setTokenValueComboBox(tokenObject.get("autoExtract").getAsBoolean(),
						tokenObject.get("staticValue").getAsBoolean(), tokenObject.get("fromToString").getAsBoolean(),
						tokenObject.get("promptForInput").getAsBoolean());
				if (tokenObject.get("extractName") != null) {
					tokenPanel.setGenericTextFieldText(tokenObject.get("extractName").getAsString());
				} else if (tokenObject.get("grepFromString") != null && tokenObject.get("grepToString") != null) {
					tokenPanel.setGenericTextFieldText("from [" + tokenObject.get("grepFromString").getAsString()
							+ "] to [" + tokenObject.get("grepToString").getAsString() + "]");
				} else if (tokenObject.get("value") != null) {
					tokenPanel.setGenericTextFieldText(tokenObject.get("value").getAsString());
				}
			}
			sessionTabbedPane.add(sessionPanel.getSessionName(), sessionPanel);
			sessionPanelMap.put(sessionPanel.getSessionName(), sessionPanel);
			if(sessionObject.get("validationConfig") != null && sessionObject.get("validationConfig").isJsonObject()) {
				SessionValidationConfig validationConfig = new Gson().fromJson(sessionObject.get("validationConfig"), SessionValidationConfig.class);
				sessionPanel.setSessionValidationConfig(validationConfig);
			}
			sessionTabbedPane.setModifEnabled(true);
		}
		mainPanel.getSessionMonitorPanel().reloadMacrosFromConfig();
		refreshSessionMacroOptions();
		mainPanel.getSessionMonitorPanel().refreshSessions();
	
		// Load Filters
		JsonArray storedFiltersArray = root.get("filters").getAsJsonArray();
		for (JsonElement filterEl : storedFiltersArray) {
			JsonObject filterObject = filterEl.getAsJsonObject();
			RequestFilter requestFilter = config.getRequestFilterAt(filterObject.get("filterIndex").getAsInt());
			requestFilter.setIsSelected(filterObject.get("isSelected").getAsBoolean());
			if (filterObject.get("stringLiterals") != null) {
				JsonArray tokenArray = filterObject.get("stringLiterals").getAsJsonArray();
				String[] stringLiterals = new String[tokenArray.size()];
				for (int i = 0; i < tokenArray.size(); i++) {
					stringLiterals[i] = tokenArray.get(i).getAsString();
				}
				requestFilter.setFilterStringLiterals(stringLiterals);
			}
		}
	}

	public void pauseButtonPressed() {
		if (config.isRunning()) {
			config.setRunning(false);
			pauseButton.setText(PLAY_TEXT);
			startStopButton.setText(ANALYZER_PAUSED_TEXT);
			startStopButton.setBackground(null); // Reset when paused
			pauseButton.setToolTipText("Currently Paused");
		} else {
			config.setRunning(true);
			pauseButton.setText(PAUSE_TEXT);
			startStopButton.setText(ANALYZER_STARTED_TEXT);
			startStopButton.setBackground(java.awt.Color.RED);
			pauseButton.setToolTipText("Currently Running");
		}
	}
	
	public boolean isPaused() {
		return pauseButton.getText().equals(PLAY_TEXT);
	}

	public void updateSessionValidationVisuals(Session session) {
		SessionPanel panel = sessionPanelMap.get(session.getName());
		if(panel != null) {
			panel.getStatusPanel().updateValidationStatus(session);
		}
		sessionTabbedPane.updateSessionValidationState(session.getName(), session.getValidationState());
		mainPanel.getSessionMonitorPanel().updateSessionRow(session);
	}

	private String[] getInputArray(Component parentFrame, String message, String value) {
		String userInput = JOptionPane.showInputDialog(parentFrame, message, value);
		if (userInput == null) {
			return null;
		}
		String[] userInputParts = userInput.split(",");
		String[] inputs = new String[userInputParts.length];
		for (int i = 0; i < inputs.length; i++) {
			inputs[i] = userInputParts[i].trim();
		}
		return inputs;
	}
}