package sessionGuard.gui.entity;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import sessionGuard.entities.MatchAndReplace;
import sessionGuard.entities.Session;
import sessionGuard.entities.SessionValidationState;
import sessionGuard.entities.Token;
import sessionGuard.util.CurrentConfig;
import sessionGuard.util.GenericHelper;

public class StatusPanel extends JPanel{
	
	private final JLabel headerLabel = new JLabel("<html><strong>Header(s) to Replace</strong></html>");
	private final JLabel headerToReplaceValue = new JLabel("");
	private final JLabel headerRemoveLabel = new JLabel("<html><strong>Header(s) to Remove</strong></html>");
	private final JLabel headerToRemoveValue = new JLabel("");
	private final JLabel amountOfFilteredRequestsLabel = new JLabel("");
	private final String SESSION_STARTED_TEXT = "Running";
	private final String SESSION_PAUSED_TEXT = "Paused";
	private boolean running = true;
	private final HashMap<String, JLabel> tokenLabelMap = new HashMap<String, JLabel>();
	private final HashMap<String, JButton> refreshButtonMap = new HashMap<String, JButton>();
	private final HashMap<String, JButton> eraseButtonMap = new HashMap<String, JButton>();
	private int amountOfFilteredRequests = 0;
	private final ImageIcon refreshIcon = new ImageIcon(this.getClass().getClassLoader().getResource("refresh.png"));
	private final ImageIcon eraseIcon = new ImageIcon(this.getClass().getClassLoader().getResource("erase.png"));
	private final JLabel validationStatusLabel = new JLabel("");
	
	private static final long serialVersionUID = -4518448060103739997L;

	public void init(Session session) {
		removeAll();
		amountOfFilteredRequests = 0;
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridy = 0;
		c.gridx = 0;
		c.anchor = GridBagConstraints.WEST;
		c.insets = new Insets(10, 0, 0, 0);
		headerLabel.putClientProperty("html.disable", null);
		add(headerLabel, c);
		
		c.gridx = 1;
		c.anchor = GridBagConstraints.NORTH;
		amountOfFilteredRequestsLabel.setText("");
		add(amountOfFilteredRequestsLabel, c);
		
		c.gridwidth = 2;
		c.gridx = 2;
		c.anchor = GridBagConstraints.WEST;
		JButton onOffSwitch = new JButton(SESSION_STARTED_TEXT);
		onOffSwitch.setOpaque(true);
		onOffSwitch.setBackground(Color.RED);
		if(!running) {
			onOffSwitch.setText(SESSION_PAUSED_TEXT);
			onOffSwitch.setBackground(null);
		}
		onOffSwitch.addActionListener(e -> {
			if(running) {
				onOffSwitch.setText(SESSION_PAUSED_TEXT);
				onOffSwitch.setBackground(null);
				running = false;
			}
			else {
				onOffSwitch.setText(SESSION_STARTED_TEXT);
				onOffSwitch.setBackground(Color.RED);
				running = true;
			}
		});		
		add(onOffSwitch, c);
		
		c.gridwidth = 4;
		c.gridx = 0;
		c.gridy++;
		c.insets = new Insets(5, 0, 0, 0);
		headerToReplaceValue.putClientProperty("html.disable", null);
		add(headerToReplaceValue, c);
		if(session.getHeadersToReplace().equals("")) {
			headerLabel.setText("                                  ");//Set ugly placeholder to keep match and replace distance
			headerToReplaceValue.setVisible(false);
		}
		else {
			headerToReplaceValue.setText(format(session.getHeadersToReplace(), session));
			headerLabel.setText("<html><p><strong>Header(s) to Replace</strong></html>");
			headerLabel.putClientProperty("html.disable", null);
			headerToReplaceValue.setVisible(true);
		}
	
		if(session.isRemoveHeaders()) {
			c.gridy++;
			c.insets = new Insets(10, 0, 0, 0);
			headerRemoveLabel.putClientProperty("html.disable", null);
			add(headerRemoveLabel, c);
			c.insets = new Insets(5, 0, 0, 0);
			c.gridy++;
			headerToRemoveValue.putClientProperty("html.disable", null);
			add(headerToRemoveValue, c);
			if(session.getHeadersToRemove().equals("")) {
				headerToRemoveValue.setText("No Headers specified");
			}
			else {
				headerToRemoveValue.setText(format(session.getHeadersToRemove(), session));
			}
		}
		c.gridy++;
		c.insets = new Insets(10, 0, 0, 0);
		validationStatusLabel.putClientProperty("html.disable", null);
		add(validationStatusLabel, c);
		updateValidationStatus(session);
		
		c.insets = new Insets(10, 0, 0, 0);
		c.gridy++;
		c.fill = GridBagConstraints.HORIZONTAL;
		if(session.getTokens().size() == 0) {
			JLabel dummyLabel = new JLabel("<html><p style='width:490px'>&nbsp;</p></html>");
			dummyLabel.putClientProperty("html.disable", null);
			c.gridwidth = 2;
			c.gridx = 0;
			add(dummyLabel, c);
		}
		for(Token token : session.getTokens()) {
			c.gridwidth = 2;
			c.gridx = 0;
			c.anchor = GridBagConstraints.WEST;
			JLabel tokenLabel = new JLabel(getTokenText(token));
			tokenLabel.putClientProperty("html.disable", null);
			tokenLabelMap.put(token.getName(), tokenLabel);
			add(tokenLabel, c);
			if(token.isAutoExtract() || token.isFromToString()) {
				c.gridx = 2;
				c.gridwidth = 1;
				c.fill = GridBagConstraints.NONE;
				JButton renewButton = new JButton(refreshIcon);
				renewButton.setToolTipText("Refresh Value");
				refreshButtonMap.put(token.getName(), renewButton);
				if(token.getRequestResponse() == null) {
					renewButton.setEnabled(false);
				}
				renewButton.addActionListener(e -> {
					if(token.getRequestResponse() != null) {
						CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(token.getRequestResponse());
					}
				});
				add(renewButton, c);
				JButton eraseButton = new JButton(eraseIcon);
				eraseButton.setToolTipText("Erase Value");
				eraseButtonMap.put(token.getName(), eraseButton);
				if(token.getValue() == null) {
					eraseButton.setEnabled(false);
				}
				eraseButton.addActionListener(e -> {
					token.setValue(null);
					updateTokenStatus(token);
				});
				c.insets = new Insets(10, 10, 0, 0);
				c.gridx = 3;
				add(eraseButton, c);
				c.insets = new Insets(10, 0, 0, 0);
			}
			c.gridy++;
		}
		if(session.getMatchAndReplaceList().size() > 0) {
			c.gridwidth = 2;
			c.gridx = 0;
			JLabel matchLabel = new JLabel("<html><strong>Match:</strong></html>");
			matchLabel.putClientProperty("html.disable", null);
			add(matchLabel, c);
			c.gridx = 1;
			JLabel replaceLabel = new JLabel("<html><strong>Replace:</strong></html>");
			replaceLabel.putClientProperty("html.disable", null);
			add(replaceLabel, c);
			c.gridy++;
			c.insets = new Insets(5, 0, 0, 0);
		}
		for(MatchAndReplace matchAndReplace : session.getMatchAndReplaceList()) {
			c.gridx = 0;
			add(new JLabel(formatMatchAndReplaceText(matchAndReplace.getMatch())), c);
			c.gridx = 1;
			add(new JLabel(formatMatchAndReplaceText(matchAndReplace.getReplace())), c);
			c.gridy++;
		}
	}
	
	private String getTokenText(Token token) {
		String tokenInfo = "";
		if(token.isAutoExtract()) {
			tokenInfo = "Auto Extract Value";
		}
		if(token.isStaticValue()) {
			tokenInfo = "Static Value";
		}
		if(token.isFromToString()) {
			tokenInfo = "Extract value from[" + token.getGrepFromString().replace("<", "&lt;") + 
					"] to [" + token.getGrepToString().replace("<", "&lt;") + "]";
		}
		if(token.isPromptForInput()) {
			tokenInfo = "Prompt for Input";
		}
		if(token.isRemove()) {
			tokenInfo = "Remove Parameter";
		}
		if(token.isAutoExtract() || token.isFromToString()) {
			if(token.getValue() != null) {
				SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
				String timestap = sdf.format(new Date());
				tokenInfo += " - Last extracted at " + timestap;
			}
		}
		String tokenValue = "<span>Value: <code>null</code></span>";
		if(token.getValue() != null) {
			String value;
			if(token.getValue().length() > 80) {
				value = token.getValue().substring(0, 80) + "...";
			}
			else {
				value = token.getValue();
			}
			if(token.isFromToString() || token.isAutoExtract()) {
				tokenValue = "Value: <code style='color:green'>" + value.replace("<", "&lt;") + "</code>";				
			}
			else {
				tokenValue = "Value: <code style='color:#00FFFF'>" + value.replace("<", "&lt;") + "</code>";
			}
		}
		if(token.isRemove()) {
			tokenValue = "Value: <code style='color:red'>[Remove Parameter]</code>";
		}
		return "<html><p style='width:500px'><strong>" + token.getName().replace("<", "&lt;").replace("\n", "<br>") + 
				"</strong> ("+tokenInfo+")</p> <p style='width:500px'>" +  tokenValue.replace("\n", "<br>") + "</p></html>";
	}
	
	private String format(String text, Session session) {
		String htmlString = "<html><p style='width:600px'>";
		for(String line : text.split("\n")) {
			int maxLength = 100;
			if(line.length() > maxLength) {
				htmlString += line.substring(0, maxLength) + "...";
			}
			else {
				htmlString += line;
			}
			htmlString += "<br>";
		}
		htmlString += "</p></html>";
		//String htmlString = "<html><p style='width:600px'>"+text.replace("<", "&lt;").replace("\n", "<br>")+"</p></html>";
		return htmlString;
	}
	
	private String formatMatchAndReplaceText(String text) {
		if(text.length() > 18) {
			return text.substring(0, 15) + "...";
		}
		return text;
	}
	
	public boolean isRunning() {
		return running;
	}
	
	public void incrementAmountOfFitleredRequests() {
		amountOfFilteredRequests++;
		amountOfFilteredRequestsLabel.setText("Amount of Filtered Requests: " + amountOfFilteredRequests);
		GenericHelper.uiUpdateAnimation(amountOfFilteredRequestsLabel, Color.RED);
	}
	
	public void updateTokenStatus(Token token) {
		JLabel tokenLabel = tokenLabelMap.get(token.getName());
		tokenLabel.putClientProperty("html.disable", null);
		tokenLabel.setText(getTokenText(token));
		GenericHelper.uiUpdateAnimation(tokenLabel, new Color(0, 153, 0));
		if(token.getValue() != null) {
			if(refreshButtonMap.get(token.getName()) != null) {
				refreshButtonMap.get(token.getName()).setEnabled(true);
			}
			if(eraseButtonMap.get(token.getName()) != null) {
				eraseButtonMap.get(token.getName()).setEnabled(true);
			}
		}
	}

	public void updateValidationStatus(Session session) {
		SessionValidationState state = session.getValidationState();
		StringBuilder text = new StringBuilder("<html><strong>Session Health:</strong> ");
		Color color = Color.DARK_GRAY;
		if(!session.getValidationConfig().isEnabled()) {
			text.append("Monitoring disabled");
		}
		else if(state == SessionValidationState.VALID) {
			text.append("<span style='color:green'>VALID</span>");
			color = new Color(0, 128, 0);
		}
		else if(state == SessionValidationState.EXPIRED) {
			text.append("<span style='color:red'>EXPIRED</span>");
			color = Color.RED;
		}
		else if(state == SessionValidationState.ERROR) {
			text.append("<span style='color:#c77400'>ERROR</span>");
			color = new Color(199, 116, 0);
		}
		else {
			text.append("Unknown");
		}
		if(session.getLastValidationTimestamp() > 0) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			text.append(" &nbsp; Last check: ").append(sdf.format(new Date(session.getLastValidationTimestamp())));
		}
		if(session.getLastValidationMessage() != null && !session.getLastValidationMessage().isEmpty()) {
			text.append("<br>").append(session.getLastValidationMessage());
		}
		text.append("</html>");
		validationStatusLabel.setText(text.toString());
		validationStatusLabel.setForeground(color);
	}
}
