package sessionGuard.gui.entity;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.UIManager;
import sessionGuard.entities.MatchAndReplace;
import sessionGuard.entities.SessionRenewalMacro;
import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.Token;
import sessionGuard.gui.dialog.MatchAndReplaceDialog;
import sessionGuard.gui.main.MainPanel;
import sessionGuard.gui.util.HintCheckBox;
import sessionGuard.gui.util.PlaceholderTextArea;
import sessionGuard.gui.util.PlaceholderTextField;
import sessionGuard.util.CurrentConfig;
import sessionGuard.util.GenericHelper;
import sessionGuard.util.Globals;

public class SessionPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private final int textFieldWidth = 70;
	private String sessionName = "";
	private final PlaceholderTextArea headersToReplaceText = new PlaceholderTextArea(3, textFieldWidth);
	private final HintCheckBox removeHeaders;
	private final JCheckBox filterRequestsWithSameHeader;
	private final HintCheckBox restrictToScope;
	private final HintCheckBox testCors;
	private final JLabel headerToRemoveLabel = new JLabel("Header(s) to Remove");
	private final PlaceholderTextArea headersToRemoveText = new PlaceholderTextArea(3, textFieldWidth);
	private final JLabel restrictToScopeLabel = new JLabel("Restrict to Scope");
	private final PlaceholderTextField restrictToScopeText = new PlaceholderTextField();
	private final JButton addTokenButton;
	private final JButton matchAndReplaceButton;
	private final JPanel sessionPanel = new JPanel();
	private final StatusPanel statusPanel = new StatusPanel();
	private final GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<TokenPanel> tokenPanels = new ArrayList<TokenPanel>();
	private ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
	private final MainPanel mainPanel;
	private final HintCheckBox validationEnabled;
	private final PlaceholderTextField validationUrlField = new PlaceholderTextField();
	private final JComboBox<String> validationMethodCombo;
	private final PlaceholderTextArea validationHeadersArea = new PlaceholderTextArea(3, textFieldWidth);
	private final PlaceholderTextArea validationBodyArea = new PlaceholderTextArea(3, textFieldWidth);
	private final PlaceholderTextField validationStatusField = new PlaceholderTextField();
	private final PlaceholderTextField validationContainsField = new PlaceholderTextField();
	private final PlaceholderTextField validationRegexField = new PlaceholderTextField();
	private final HintCheckBox validationUseRegex;
	private final JComboBox<String> macroSelectionCombo = new JComboBox<>();
	private final JButton manageMacrosButton = new JButton("Manage Macros");
	private String pendingMacroName = "";

	public SessionPanel(String sessionName, MainPanel mainPanel) {
		this.sessionName = sessionName;
		this.mainPanel = mainPanel;
		sessionPanel.setLayout(new GridBagLayout());
		c.gridx = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridwidth = 4;
		c.weighty = 1;
		
		statusPanel.setVisible(false);
		add(statusPanel, c);
		setupContextMenu();

		// Two-column layout for session configuration
		JPanel headerColumn = new JPanel(new GridBagLayout());
		GridBagConstraints hc = new GridBagConstraints();
		hc.gridx = 0;
		hc.gridy = 0;
		hc.anchor = GridBagConstraints.WEST;
		hc.fill = GridBagConstraints.HORIZONTAL;
		hc.gridwidth = 2;
		hc.weightx = 1.0;

		JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
		headerColumn.add(headerToReplaceLabel, hc);
		hc.gridy++;
		headersToReplaceText.setPlaceholder("Cookie: Session=d3c2b484-5fed-11eb-ae93-0242ac130002;"); 
		headersToReplaceText.setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		headersToReplaceText.putClientProperty("html.disable", null);
		headerColumn.add(headersToReplaceText, hc);

		removeHeaders = new HintCheckBox("Remove Header(s)", false, "The defined Headers will be removed");
		hc.gridwidth = 1;
		hc.insets = new Insets(5, 0, 0, 10);
		hc.gridy++;
		headerColumn.add(removeHeaders, hc);
		
		filterRequestsWithSameHeader = new JCheckBox("Filter requests with same header(s)", false);
		hc.gridx = 0;
		hc.gridy++;
		hc.anchor = GridBagConstraints.WEST;
		restrictToScope = new HintCheckBox("Restrict to Scope", false, "Session will only be repeated for defined Scope / Path");
		headerColumn.add(restrictToScope, hc);
		
		hc.gridx = 1;
		testCors = new HintCheckBox("Test CORS", false, "HTTP Method will be set to OPTIONS");
		headerColumn.add(testCors, hc);
		
		hc.gridx = 0;
		hc.gridy++;
		hc.gridwidth = 2;
		headerToRemoveLabel.setVisible(false);
		headerColumn.add(headerToRemoveLabel, hc);
		hc.gridy++;
		headersToRemoveText.setPlaceholder("Cookie:"); 
		headersToRemoveText.setVisible(false);
		headerColumn.add(headersToRemoveText, hc);
		removeHeaders.addActionListener(e -> updateGui());		
		
		hc.gridy++;
		hc.insets = new Insets(5, 0, 0, 0);
		restrictToScopeLabel.setVisible(false);
		headerColumn.add(restrictToScopeLabel, hc);
		hc.gridy++;
		restrictToScopeText.setPlaceholder("https://restrict_to_this.domain/restrict/to/this/path");
		restrictToScopeText.setVisible(false);
		headerColumn.add(restrictToScopeText, hc);
		restrictToScope.addActionListener(e -> updateGui());
		
		JPanel monitoringColumn = new JPanel(new GridBagLayout());
		GridBagConstraints mc = new GridBagConstraints();
		mc.gridx = 0;
		mc.gridy = 0;
		mc.anchor = GridBagConstraints.WEST;
		mc.fill = GridBagConstraints.HORIZONTAL;
		mc.weightx = 1.0;
		mc.gridwidth = 2;

		JLabel validationLabel = new JLabel("Session Monitoring");
		validationLabel.setToolTipText("Automatically validate session health via a probe request");
		monitoringColumn.add(validationLabel, mc);

		mc.gridy++;
		validationEnabled = new HintCheckBox("Enable Session Monitoring", false,
				"Send a probe request and mark session expired if the response does not match the expectations");
		monitoringColumn.add(validationEnabled, mc);
		validationEnabled.addActionListener(e -> updateValidationControls());

		mc.gridy++;
		mc.gridwidth = 2;
		mc.fill = GridBagConstraints.NONE;
		mc.weightx = 0;
		JPanel validationRow = new JPanel(new GridBagLayout());
		GridBagConstraints v = new GridBagConstraints();
		v.gridx = 0;
		v.gridy = 0;
		v.insets = new Insets(0, 0, 0, 5);
		v.anchor = GridBagConstraints.WEST;
		validationUrlField.setPlaceholder("https://target/app/health");
		validationUrlField.setToolTipText("Endpoint used to validate session health");
		validationUrlField.setColumns(35);
		validationRow.add(new JLabel("Target URL:"), v);
		v.gridx++;
		v.fill = GridBagConstraints.HORIZONTAL;
		v.weightx = 1.0;
		validationRow.add(validationUrlField, v);
		v.gridx++;
		v.fill = GridBagConstraints.NONE;
		v.weightx = 0;
		String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH"};
		validationMethodCombo = new JComboBox<>(methods);
		validationMethodCombo.setToolTipText("HTTP method for the validation request");
		validationRow.add(validationMethodCombo, v);
		mc.gridwidth = 2;
		mc.fill = GridBagConstraints.HORIZONTAL;
		mc.weightx = 1.0;
		monitoringColumn.add(validationRow, mc);

		mc.gridy++;
		mc.gridwidth = 2;
		mc.fill = GridBagConstraints.BOTH;
		mc.weightx = 1.0;
		mc.weighty = 0;
		mc.insets = new Insets(5, 0, 5, 0);
		JPanel headerBodyPanel = new JPanel(new GridBagLayout());
		GridBagConstraints hb = new GridBagConstraints();
		hb.gridx = 0;
		hb.gridy = 0;
		hb.insets = new Insets(0, 5, 5, 5);
		hb.anchor = GridBagConstraints.WEST;
		hb.fill = GridBagConstraints.NONE;
		hb.weightx = 0;
		headerBodyPanel.add(new JLabel("Request Headers"), hb);
		hb.gridx++;
		hb.anchor = GridBagConstraints.WEST;
		headerBodyPanel.add(new JLabel("Request Body"), hb);
		hb.gridy++;
		hb.gridx = 0;
		hb.fill = GridBagConstraints.BOTH;
		hb.weightx = 0.5;
		hb.weighty = 1.0;
		hb.insets = new Insets(0, 5, 0, 5);
		validationHeadersArea.setPlaceholder("Header: value");
		validationHeadersArea.setToolTipText("Additional headers for validation request. One per line.");
		validationHeadersArea.setRows(4);
		validationHeadersArea.setColumns(30);
		javax.swing.JScrollPane headersScroll = new javax.swing.JScrollPane(validationHeadersArea);
		headersScroll.setPreferredSize(new java.awt.Dimension(0, 100));
		headerBodyPanel.add(headersScroll, hb);
		hb.gridx++;
		hb.weightx = 0.5;
		validationBodyArea.setPlaceholder("{\"example\":\"value\"}");
		validationBodyArea.setToolTipText("Optional body for POST/PUT validation requests.");
		validationBodyArea.setRows(4);
		validationBodyArea.setColumns(30);
		javax.swing.JScrollPane bodyScroll = new javax.swing.JScrollPane(validationBodyArea);
		bodyScroll.setPreferredSize(new java.awt.Dimension(0, 100));
		headerBodyPanel.add(bodyScroll, hb);
		monitoringColumn.add(headerBodyPanel, mc);

		mc.gridy++;
		mc.gridwidth = 2;
		mc.fill = GridBagConstraints.HORIZONTAL;
		mc.weightx = 1.0;
		mc.weighty = 0;
		mc.insets = new Insets(5, 0, 5, 0);
		JPanel expectationPanel = new JPanel(new GridBagLayout());
		GridBagConstraints ex = new GridBagConstraints();
		ex.insets = new Insets(0, 5, 0, 5);
		ex.anchor = GridBagConstraints.WEST;
		ex.fill = GridBagConstraints.NONE;
		ex.weightx = 0;
		ex.gridx = 0;
		ex.gridy = 0;
		expectationPanel.add(new JLabel("Expected Status"), ex);
		ex.gridy++;
		ex.gridx = 0;
		validationStatusField.setPlaceholder("200");
		validationStatusField.setToolTipText("Expected HTTP status code (e.g., 200)");
		validationStatusField.setColumns(6);
		expectationPanel.add(validationStatusField, ex);
		ex.gridy = 0;
		ex.gridx = 1;
		expectationPanel.add(new JLabel("Response must contain"), ex);
		ex.gridx++;
		expectationPanel.add(new JLabel("Regex match"), ex);
		ex.gridy = 1;
		ex.gridx = 1;
		ex.fill = GridBagConstraints.HORIZONTAL;
		ex.weightx = 0.5;
		validationContainsField.setPlaceholder("success");
		validationContainsField.setToolTipText("Expected substring present in response body");
		validationContainsField.setColumns(18);
		expectationPanel.add(validationContainsField, ex);
		ex.gridx++;
		ex.weightx = 0.5;
		validationRegexField.setPlaceholder("token=([A-Za-z0-9]+)");
		validationRegexField.setToolTipText("Regex pattern to match in response body");
		validationRegexField.setColumns(18);
		expectationPanel.add(validationRegexField, ex);
		ex.gridy++;
		ex.gridx = 0;
		ex.gridwidth = 3;
		ex.fill = GridBagConstraints.NONE;
		ex.weightx = 0;
		validationUseRegex = new HintCheckBox("Use regex", false, "Match response body using regex instead of plain substring");
		expectationPanel.add(validationUseRegex, ex);
		monitoringColumn.add(expectationPanel, mc);

		// place columns within main layout
		c.gridy = 0;
		c.gridx = 0;
		c.gridwidth = 2;
		c.weightx = 0.5;
		c.insets = new Insets(0, 0, 0, 10);
		sessionPanel.add(headerColumn, c);

		c.gridx = 2;
		c.weightx = 0.5;
		c.insets = new Insets(0, 10, 0, 0);
		sessionPanel.add(monitoringColumn, c);
		c.gridy++;
		c.gridx = 0;
		c.gridwidth = 4;
		c.weightx = 1.0;
		c.insets = new Insets(5, 0, 0, 0);
		c.fill = GridBagConstraints.HORIZONTAL;

		c.gridy++;
		c.gridwidth = 4;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 1.0;
		JPanel macroPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
		macroPanel.add(new JLabel("Renewal Macro:"));
		macroSelectionCombo.setPrototypeDisplayValue("Select macro...");
		macroSelectionCombo.addActionListener(e -> pendingMacroName = getSelectedMacroName());
		macroPanel.add(macroSelectionCombo);
		JButton refreshMacroButton = new JButton("Refresh");
		refreshMacroButton.setToolTipText("Reload available renewal macros");
		refreshMacroButton.addActionListener(e -> refreshMacroOptions());
		macroPanel.add(refreshMacroButton);
		manageMacrosButton.addActionListener(e -> mainPanel.showSessionMonitorTab());
		manageMacrosButton.setToolTipText("Open Macro Manager to create or edit renewal macros");
		macroPanel.add(manageMacrosButton);
		sessionPanel.add(macroPanel, c);
		refreshMacroOptions();
		updateValidationControls();

		JPanel buttonPanel = new JPanel();
		addTokenButton = new JButton("Add Parameter");
		addTokenButton.setToolTipText("Add a parameter/token to extract and replace");
		addTokenButton.addActionListener(e -> addToken());
		buttonPanel.add(addTokenButton);
		matchAndReplaceButton = new JButton("Match and Replace");
		matchAndReplaceButton.setToolTipText("Define match-and-replace rules for headers/parameters");
		matchAndReplaceButton.addActionListener(e -> {
			new MatchAndReplaceDialog(this);
		});
		buttonPanel.add(matchAndReplaceButton);
		JButton infoButton = new JButton("?");
		infoButton.addActionListener(e -> {
			
			try {
				Desktop.getDesktop().browse(new URI(Globals.URL_GITHUB_PARAMETER_HELP));
			} catch (Exception e1) {
				JOptionPane.showMessageDialog(this, "Browser can not be opened.", "Error", JOptionPane.WARNING_MESSAGE);
			}
		});
		buttonPanel.add(infoButton);
		c.gridy++;
		c.fill = GridBagConstraints.VERTICAL;
		sessionPanel.add(buttonPanel, c);
		c.insets = new Insets(0, 0, 0, 0);
		add(sessionPanel);
	}
	
	private void updateGui() {
		if(removeHeaders.isSelected()) {
			headerToRemoveLabel.setVisible(true);
			headersToRemoveText.setVisible(true);
		}
		else {
			headerToRemoveLabel.setVisible(false);
			headersToRemoveText.setVisible(false);
		}
		if(restrictToScope.isSelected()) {
			restrictToScopeLabel.setVisible(true);
			restrictToScopeText.setVisible(true);
		}
		else {
			restrictToScopeLabel.setVisible(false);
			restrictToScopeText.setVisible(false);
		}
		revalidate();
		mainPanel.updateDividerLocation();
	}
	
	public void updateMatchAndReplaceButtonText() {
		if(matchAndReplaceList.size() > 0) {
			matchAndReplaceButton.setText("Match and Replace (" + matchAndReplaceList.size() + ")");
		}
		else {
			matchAndReplaceButton.setText("Match and Replace");
		}
	}

	public void setRunning() {
		statusPanel.setVisible(true);
		sessionPanel.setVisible(false);
	}

	public void setStopped() {
		statusPanel.setVisible(false);
		sessionPanel.setVisible(true);
	}

	private TokenPanel addToken() {
		TokenPanel tokenPanel = new TokenPanel();
		if(tokenPanels.size() > 0) {
			tokenPanel.setHeaderVisible(false);
		}
		tokenPanels.add(tokenPanel);
		c.gridy++;
		sessionPanel.add(tokenPanel, c);
		sessionPanel.revalidate();
		
		tokenPanel.getRemoveButton().addActionListener(e -> {
			sessionPanel.remove(tokenPanel);
			tokenPanels.remove(tokenPanel);
			if(tokenPanels.size() > 0) {
				tokenPanels.get(0).setHeaderVisible(true);
			}
			revalidate();
			mainPanel.updateDividerLocation();
		});
		mainPanel.updateDividerLocation();
		return tokenPanel;
	}
	
	public TokenPanel addToken(String name) {
		TokenPanel tokenPanel = addToken();
		tokenPanel.setTokenName(name);
		//Set Token Extract Field Name as well
		tokenPanel.setAutoExtractFieldName(name);
		return tokenPanel;
	}
	
	public TokenPanel addToken(Token token) {
		TokenPanel tokenPanel = addToken(token.getName());
		tokenPanel.setTokenLocationSet(token.getTokenLocationSet());
		tokenPanel.setTokenLocationSet(token.getTokenLocationSet());
		tokenPanel.setAutoExtractLocationSet(token.getAutoExtractLocationSet());
		tokenPanel.setFromToExtractLocationSet(token.getFromToExtractLocationSet());
		tokenPanel.setCaseSensitiveTokenName(token.isCaseSensitiveTokenName());
		tokenPanel.setIsRemoveToken(token.isRemove());
		tokenPanel.setAddTokenIfNotExists(token.isAddIfNotExists());
		if (token.isAutoExtract()) {
			tokenPanel.setAutoExtractFieldName(token.getExtractName());
		}
		if (token.isStaticValue()) {
			tokenPanel.setStaticTokenValue(token.getValue());
		}
		if (token.isFromToString()) {
			tokenPanel.setFromToString(token.getGrepFromString(), token.getGrepToString());
		}
		if (token.isPromptForInput()) {
			tokenPanel.setPromptForInput();
		}
		return tokenPanel;
	}
	
	public boolean tokensValid() {
		ArrayList<String> tokenNames = new ArrayList<String>();
		for (TokenPanel tokenPanel : tokenPanels) {
			tokenPanel.setDefaultColorAllTextFields();
			// Token Name can not be empty
			if (tokenPanel.getTokenName().equals("")) {
				tokenPanel.setRedColorNameTextField();
				showValidationFailedDialog("You are not allowed to use empty parameter names\nAffected Session: " + getSessionName() );
				return false;
			}
			// Extract Field Name can not be empty (if selected)
			if (tokenPanel.isAutoExtract() && tokenPanel.getAutoExtractFieldName().equals("")) {
				tokenPanel.setRedColorGenericTextField();
				showValidationFailedDialog("You are not allowed to use an empty \"Extract Field Name\"\nAffected Session: "  + 
			getSessionName() + "\nAffected Parameter: " + tokenPanel.getTokenName());
				return false;
			}
			// From To String must be in correct format (if selected)
			if (tokenPanel.isFromToString() && tokenPanel.getFromToStringArray() == null) {
				tokenPanel.setRedColorGenericTextField();
				showValidationFailedDialog("\"From To String\" not correctly formatted\nAffected Session: "  + getSessionName() +
						"\nAffected Parameter: " + tokenPanel.getTokenName());
				tokenPanel.setGenericTextFieldText("from [] to []");
				return false;
			}
			// Check for duplicated Names
			if (tokenNames.contains(tokenPanel.getTokenName())) {
				tokenPanel.setRedColorNameTextField();
				showValidationFailedDialog(
						"You are not allowed to use duplicated parameter names\nAffected Session: " + getSessionName() +
						"\nAffected Parameter: " + tokenPanel.getTokenName());
				return false;
			}
			tokenNames.add(tokenPanel.getTokenName());
		}
		return true;
	}

	public boolean isHeaderValid() {
		headersToReplaceText.setBackground(UIManager.getColor("TextArea.background"));
		//Allow empty header
		if(headersToReplaceText.getText().equals("")) {
			return true;
		}
		boolean valid = true;
		String[] headerLines = headersToReplaceText.getText().replace("\r", "").split("\n");
		if(headerLines.length == 0) {
			valid = false;
		}
		for(String header : headerLines) {
			String[] keyValueSplit = header.split(":");
			if(keyValueSplit.length < 2) {
				valid = false;
			}
		}
		if(!valid) {
			showValidationFailedDialog("The definied Header(s) to replace are not valid. \nAffected Session: " + getSessionName());
			headersToReplaceText.setBackground(GenericHelper.getErrorBgColor());
			return false;
		}
		else {
			return true;
		}
	}
	
	public boolean isScopeValid() {
		restrictToScopeText.setBackground(UIManager.getColor("TextArea.background"));
		if(restrictToScope.isSelected()) {
			try {
				new URL(restrictToScopeText.getText());
			} catch (MalformedURLException e) {
				showValidationFailedDialog("The definied scope URL is not valid\nAffected Session: " +	getSessionName());
				restrictToScopeText.setBackground(GenericHelper.getErrorBgColor());
				return false;
			}
		}
		return true;
	}
	
	public void setMatchAndReplaceList(ArrayList<MatchAndReplace> matchAndReplaceList) {
		this.matchAndReplaceList = matchAndReplaceList;
		updateMatchAndReplaceButtonText();
	}

	public SessionValidationConfig getSessionValidationConfig() {
		SessionValidationConfig config = new SessionValidationConfig();
		config.setEnabled(validationEnabled.isSelected());
		config.setTargetUrl(validationUrlField.getText());
		config.setHttpMethod(validationMethodCombo.getSelectedItem().toString());
		config.setRequestHeaders(validationHeadersArea.getText());
		config.setRequestBody(validationBodyArea.getText());
		config.setExpectedStatusCode(parseStatusCode(validationStatusField.getText()));
		config.setExpectedBodySubstring(validationContainsField.getText());
		config.setExpectedBodyRegex(validationRegexField.getText());
		config.setUseRegex(validationUseRegex.isSelected());
		config.setRenewalMacroName(getSelectedMacroName());
		return config;
	}

	public void setSessionValidationConfig(SessionValidationConfig config) {
		if(config == null) {
			return;
		}
		validationEnabled.setSelected(config.isEnabled());
		if(config.getTargetUrl() != null) {
			validationUrlField.setText(config.getTargetUrl());
		}
		if(config.getHttpMethod() != null) {
			validationMethodCombo.setSelectedItem(config.getHttpMethod());
		}
		if(config.getRequestHeaders() != null) {
			validationHeadersArea.setText(config.getRequestHeaders());
		}
		if(config.getRequestBody() != null) {
			validationBodyArea.setText(config.getRequestBody());
		}
		validationStatusField.setText(String.valueOf(config.getExpectedStatusCode()));
		if(config.getExpectedBodySubstring() != null) {
			validationContainsField.setText(config.getExpectedBodySubstring());
		}
		if(config.getExpectedBodyRegex() != null) {
			validationRegexField.setText(config.getExpectedBodyRegex());
		}
		validationUseRegex.setSelected(config.isUseRegex());
		pendingMacroName = config.getRenewalMacroName();
		refreshMacroOptions();
		updateValidationControls();
	}

	public void applyValidationTemplate(String url, String method, String headers, String body) {
		if(url != null) {
			validationUrlField.setText(url);
		}
		if(method != null) {
			selectValidationMethod(method);
		}
		if(headers != null) {
			validationHeadersArea.setText(headers);
		}
		if(body != null) {
			validationBodyArea.setText(body);
		}
	}

	private void selectValidationMethod(String method) {
		boolean found = false;
		for(int i = 0; i < validationMethodCombo.getItemCount(); i++) {
			if(validationMethodCombo.getItemAt(i).equalsIgnoreCase(method)) {
				found = true;
				break;
			}
		}
		if(!found && method != null && !method.isEmpty()) {
			validationMethodCombo.addItem(method);
		}
		if(method != null && !method.isEmpty()) {
			validationMethodCombo.setSelectedItem(method);
		}
	}

	private int parseStatusCode(String input) {
		if(input == null || input.trim().isEmpty()) {
			return 200;
		}
		try {
			return Integer.parseInt(input.trim());
		}
		catch (NumberFormatException e) {
			return 200;
		}
	}

	private void updateValidationControls() {
		boolean enabled = validationEnabled.isSelected();
		validationUrlField.setEnabled(enabled);
		validationMethodCombo.setEnabled(enabled);
		validationHeadersArea.setEnabled(enabled);
		validationBodyArea.setEnabled(enabled);
		validationStatusField.setEnabled(enabled);
		validationContainsField.setEnabled(enabled);
		validationRegexField.setEnabled(enabled);
		validationUseRegex.setEnabled(enabled);
		macroSelectionCombo.setEnabled(enabled);
	}

	public void refreshMacroOptions() {
		String desiredSelection = pendingMacroName != null && !pendingMacroName.isEmpty()
				? pendingMacroName
				: getSelectedMacroName();
		DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
		model.addElement("None");
		for(SessionRenewalMacro macro : CurrentConfig.getCurrentConfig().getRenewalMacros()) {
			if(macro.getName() != null && !macro.getName().isEmpty()) {
				model.addElement(macro.getName());
			}
		}
		macroSelectionCombo.setModel(model);
		if(desiredSelection != null && !desiredSelection.isEmpty() && model.getIndexOf(desiredSelection) != -1) {
			model.setSelectedItem(desiredSelection);
			pendingMacroName = desiredSelection;
		}
		else {
			model.setSelectedItem("None");
		}
	}

	private String getSelectedMacroName() {
		Object selected = macroSelectionCombo.getSelectedItem();
		if(selected == null) {
			return "";
		}
		String value = selected.toString();
		if("None".equalsIgnoreCase(value)) {
			return "";
		}
		return value;
	}
	
	public ArrayList<MatchAndReplace> getMatchAndReplaceList() {
		return matchAndReplaceList;
	}
	
	public URL getScopeUrl() {
		if(restrictToScope.isSelected()) {
			try {
				URL scopeUrl = new URL(restrictToScopeText.getText());
				return scopeUrl;
			} catch (MalformedURLException e) {
				return null;
			}
		}
		return null;
	}
	
	private void showValidationFailedDialog(String text) {
		JOptionPane.showMessageDialog(this, text, "Validation Failed", JOptionPane.WARNING_MESSAGE);
	}

	private void setupContextMenu() {
		headersToReplaceText.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.getButton() == MouseEvent.BUTTON3 && headersToReplaceText.getSelectedText() != null
						&& tokenPanels.size() > 0) {
					JPopupMenu contextMenu = new JPopupMenu();
					for (TokenPanel tokenPanel : tokenPanels) {
						JMenuItem item = new JMenuItem("Set Insertion Point for " + tokenPanel.getTokenName());
						String textWithReplacement = headersToReplaceText.getText().substring(0,
								headersToReplaceText.getSelectionStart()) + Globals.INSERTION_POINT_IDENTIFIER + tokenPanel.getTokenName() + Globals.INSERTION_POINT_IDENTIFIER
								+ headersToReplaceText.getText().substring(headersToReplaceText.getSelectionEnd());
						item.addActionListener(e -> headersToReplaceText.setText(textWithReplacement));
						contextMenu.add(item);
					}
					contextMenu.show(event.getComponent(), event.getX(), event.getY());
				} else {
					super.mouseReleased(event);
				}
			}
		});
	}

	public StatusPanel getStatusPanel() {
		return statusPanel;
	}

	public String getHeadersToReplaceText() {
		return headersToReplaceText.getText();
	}

	public void setHeadersToReplaceText(String text) {
		this.headersToReplaceText.setText(text);
	}
	
	public String getHeadersToRemoveText() {
		return headersToRemoveText.getText();
	}
	
	public void setHeadersToRemoveText(String text) {
		this.headersToRemoveText.setText(text);
	}

	public void appendHeadersToReplaceText(String selectedText) {
		if (getHeadersToReplaceText().endsWith("\n") || getHeadersToReplaceText().equals("")) {
			setHeadersToReplaceText(getHeadersToReplaceText() + selectedText);
		} else {
			setHeadersToReplaceText(getHeadersToReplaceText() + "\n" + selectedText);
		}
	}
	
	public boolean isRemoveHeaders() {
		return removeHeaders.isSelected();
	}
	
	public void setRemoveHeaders(boolean removeHeaders) {
		this.removeHeaders.setSelected(removeHeaders);
		updateGui();
	}

	public boolean isFilterRequestsWithSameHeader() {
		return filterRequestsWithSameHeader.isSelected();
	}

	public void setFilterRequestsWithSameHeader(boolean filterRequestsWithSameHeader) {
		this.filterRequestsWithSameHeader.setSelected(filterRequestsWithSameHeader);
	}
	
	public boolean isRestrictToScope() {
		return restrictToScope.isSelected();
	}
	
	public void setTestCors(boolean testCors) {
		this.testCors.setSelected(testCors);
	}
	
	public boolean isTestCors() {
		return testCors.isSelected();
	}
	
	public void setRestrictToScope(boolean restrictToScope) {
		this.restrictToScope.setSelected(restrictToScope);
		updateGui();
	}
	
	public void setRestrictToScopeText(String text) {
		this.restrictToScopeText.setText(text);
	}
	public String getRestrictToScopeText() {
		return restrictToScopeText.getText();
	}

	public ArrayList<TokenPanel> getTokenPanelList() {
		return tokenPanels;
	}

	public String getSessionName() {
		return sessionName;
	}

	public void setSessionName(String sessionName) {
		this.sessionName = sessionName;
	}
}
