package sessionGuard.gui.main;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import sessionGuard.entities.Session;
import sessionGuard.entities.SessionMacroStep;
import sessionGuard.entities.SessionRenewalMacro;
import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.SessionValidationState;
import sessionGuard.gui.util.PlaceholderTextArea;
import sessionGuard.util.CurrentConfig;
import sessionGuard.util.SessionValidationManager;

public class SessionMonitorPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private final MacroManagerPanel macroManagerPanel;
	private final SessionStatusPanel statusPanel;
	private final JTabbedPane tabbedPane;

	public SessionMonitorPanel(MainPanel mainPanel) {
		setLayout(new BorderLayout());
		macroManagerPanel = new MacroManagerPanel(mainPanel);
		statusPanel = new SessionStatusPanel();
		tabbedPane = new JTabbedPane();
		tabbedPane.addTab("Renewal Macros", macroManagerPanel);
		tabbedPane.addTab("Session Status", statusPanel);
		add(tabbedPane, BorderLayout.CENTER);
	}

	public void refreshSessions() {
		statusPanel.refreshSessions();
	}

	public void updateSessionRow(Session session) {
		statusPanel.updateSessionRow(session);
	}

	public void reloadMacrosFromConfig() {
		macroManagerPanel.reloadFromConfig();
	}

	public void showMacroManager() {
		tabbedPane.setSelectedComponent(macroManagerPanel);
	}

	private static class MacroManagerPanel extends JPanel {

		private static final long serialVersionUID = 1L;
		private final MainPanel mainPanel;
		private final CurrentConfig config = CurrentConfig.getCurrentConfig();
		private final DefaultListModel<SessionRenewalMacro> macroListModel = new DefaultListModel<>();
		private final JList<SessionRenewalMacro> macroList = new JList<>(macroListModel);
		private final DefaultListModel<SessionMacroStep> stepListModel = new DefaultListModel<>();
		private final JList<SessionMacroStep> stepList = new JList<>(stepListModel);
		private final JTextField nameField = new JTextField();
		private final JTextArea descriptionArea = new JTextArea(3, 30);
		private boolean loading = false;

		MacroManagerPanel(MainPanel mainPanel) {
			this.mainPanel = mainPanel;
			setLayout(new BorderLayout(10, 10));
			setBorder(new EmptyBorder(10, 10, 10, 10));
			buildMacroListPanel();
			buildDetailsPanel();
			reloadFromConfig();
		}

		private void buildMacroListPanel() {
			JPanel listPanel = new JPanel(new BorderLayout(5, 5));
			listPanel.setBorder(BorderFactory.createTitledBorder("Available Macros"));
			macroList.setCellRenderer(new DefaultListCellRenderer() {
				private static final long serialVersionUID = 1L;
				@Override
				public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index,
						boolean isSelected, boolean cellHasFocus) {
					JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected,
							cellHasFocus);
					if(value instanceof SessionRenewalMacro) {
						SessionRenewalMacro macro = (SessionRenewalMacro) value;
						label.setText(macro.getName() + " (" + macro.getSteps().size() + " steps)");
					}
					return label;
				}
			});
			macroList.addListSelectionListener(e -> {
				if(!e.getValueIsAdjusting()) {
					loadSelectedMacro();
				}
			});
			listPanel.add(new JScrollPane(macroList), BorderLayout.CENTER);

			JPanel buttonPanel = new JPanel();
			JButton addButton = new JButton("New");
			addButton.addActionListener(e -> addMacro());
			JButton duplicateButton = new JButton("Duplicate");
			duplicateButton.addActionListener(e -> duplicateMacro());
			JButton deleteButton = new JButton("Delete");
			deleteButton.addActionListener(e -> deleteMacro());
			buttonPanel.add(addButton);
			buttonPanel.add(duplicateButton);
			buttonPanel.add(deleteButton);
			listPanel.add(buttonPanel, BorderLayout.SOUTH);
			add(listPanel, BorderLayout.WEST);
		}

		private void buildDetailsPanel() {
			JPanel detailPanel = new JPanel(new GridBagLayout());
			detailPanel.setBorder(BorderFactory.createTitledBorder("Macro Details"));
			GridBagConstraints c = new GridBagConstraints();
			c.insets = new Insets(5, 5, 5, 5);
			c.anchor = GridBagConstraints.WEST;
			c.fill = GridBagConstraints.HORIZONTAL;
			c.gridx = 0;
			c.gridy = 0;
			detailPanel.add(new JLabel("Name"), c);
			c.gridx = 1;
			c.weightx = 1;
			detailPanel.add(nameField, c);
			nameField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
				if(loading) return;
				SessionRenewalMacro macro = macroList.getSelectedValue();
				if(macro != null) {
					String newName = nameField.getText().trim();
					if(newName.isEmpty()) {
						JOptionPane.showMessageDialog(this, "Macro name cannot be empty.", "Invalid Name",
								JOptionPane.WARNING_MESSAGE);
						nameField.setText(macro.getName());
						return;
					}
					// Check for duplicate names (excluding current macro)
					for(int i = 0; i < macroListModel.size(); i++) {
						SessionRenewalMacro other = macroListModel.getElementAt(i);
						if(other != macro && newName.equals(other.getName())) {
							JOptionPane.showMessageDialog(this, "Macro name already exists.", "Duplicate Name",
									JOptionPane.WARNING_MESSAGE);
							nameField.setText(macro.getName());
							return;
						}
					}
					macro.setName(newName);
					macroList.repaint();
					persistMacros();
				}
			}));

			c.gridx = 0;
			c.gridy++;
			c.weightx = 0;
			detailPanel.add(new JLabel("Description"), c);
			c.gridx = 1;
			descriptionArea.setLineWrap(true);
			descriptionArea.setWrapStyleWord(true);
			JScrollPane descriptionScroll = new JScrollPane(descriptionArea);
			detailPanel.add(descriptionScroll, c);
			descriptionArea.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
				if(loading) return;
				SessionRenewalMacro macro = macroList.getSelectedValue();
				if(macro != null) {
					macro.setDescription(descriptionArea.getText().trim());
					persistMacros();
				}
			}));

			c.gridx = 0;
			c.gridy++;
			c.gridwidth = 2;
			c.weightx = 1;
			c.fill = GridBagConstraints.BOTH;
			JPanel stepsPanel = new JPanel(new BorderLayout(5, 5));
			stepsPanel.setBorder(BorderFactory.createTitledBorder("Macro Steps"));
			stepList.setCellRenderer(new DefaultListCellRenderer() {
				private static final long serialVersionUID = 1L;
				@Override
				public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index,
						boolean isSelected, boolean cellHasFocus) {
					JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected,
							cellHasFocus);
					if(value instanceof SessionMacroStep) {
						SessionMacroStep step = (SessionMacroStep) value;
						label.setText(step.getMethod() + " " + step.getUrl());
					}
					return label;
				}
			});
			stepsPanel.add(new JScrollPane(stepList), BorderLayout.CENTER);

			JPanel stepButtons = new JPanel();
			JButton addStepButton = new JButton("Add");
			addStepButton.addActionListener(this::addStep);
			JButton editStepButton = new JButton("Edit");
			editStepButton.addActionListener(this::editStep);
			JButton removeStepButton = new JButton("Remove");
			removeStepButton.addActionListener(e -> removeStep());
			JButton upStepButton = new JButton("Up");
			upStepButton.addActionListener(e -> moveStep(-1));
			JButton downStepButton = new JButton("Down");
			downStepButton.addActionListener(e -> moveStep(1));
			stepButtons.add(addStepButton);
			stepButtons.add(editStepButton);
			stepButtons.add(removeStepButton);
			stepButtons.add(upStepButton);
			stepButtons.add(downStepButton);
			stepsPanel.add(stepButtons, BorderLayout.SOUTH);

			JLabel hintLabel = new JLabel("Use [[PARAM_NAME]] to insert session parameters.");
			hintLabel.setForeground(Color.DARK_GRAY);
			stepsPanel.add(hintLabel, BorderLayout.NORTH);

			detailPanel.add(stepsPanel, c);
			add(detailPanel, BorderLayout.CENTER);
		}

		private void addMacro() {
			SessionRenewalMacro macro = new SessionRenewalMacro();
			macro.setName("Macro " + (macroListModel.size() + 1));
			macroListModel.addElement(macro);
			macroList.setSelectedValue(macro, true);
			persistMacros();
		}

		private void duplicateMacro() {
			SessionRenewalMacro selected = macroList.getSelectedValue();
			if(selected == null) {
				return;
			}
			SessionRenewalMacro duplicate = new SessionRenewalMacro();
			duplicate.setName(selected.getName() + " Copy");
			duplicate.setDescription(selected.getDescription());
			duplicate.setSteps(new ArrayList<>(selected.getSteps()));
			macroListModel.addElement(duplicate);
			macroList.setSelectedValue(duplicate, true);
			persistMacros();
		}

		private void deleteMacro() {
			SessionRenewalMacro selected = macroList.getSelectedValue();
			if(selected == null) {
				return;
			}
			if(macroListModel.size() == 1) {
				JOptionPane.showMessageDialog(this, "At least one macro must exist.", "Cannot delete",
						JOptionPane.WARNING_MESSAGE);
				return;
			}
			// Check if any session references this macro
		java.util.List<String> referencingSessions = new ArrayList<>();
		for(Session session : config.getSessions()) {
			SessionValidationConfig validationConfig = session.getValidationConfig();
			if(validationConfig != null) {
					String macroName = validationConfig.getRenewalMacroName();
					if(macroName != null && selected.getName().equals(macroName)) {
						referencingSessions.add(session.getName());
					}
				}
			}
			if(!referencingSessions.isEmpty()) {
				JOptionPane.showMessageDialog(this, 
					"Cannot delete macro. It is used by the following session(s):\n" + 
					String.join(", ", referencingSessions) + "\n\nPlease change the macro assignment in these sessions first.",
					"Cannot delete", JOptionPane.WARNING_MESSAGE);
				return;
			}
			macroListModel.removeElement(selected);
			if(!macroListModel.isEmpty()) {
				macroList.setSelectedIndex(0);
			}
			persistMacros();
		}

		private void addStep(ActionEvent e) {
			SessionMacroStep newStep = showStepDialog(null);
			if(newStep == null) {
				return;
			}
			SessionRenewalMacro macro = macroList.getSelectedValue();
			if(macro == null) {
				return;
			}
			macro.addStep(newStep);
			stepListModel.addElement(newStep);
			stepList.setSelectedValue(newStep, true);
			persistMacros();
		}

		private void editStep(ActionEvent e) {
			SessionMacroStep selectedStep = stepList.getSelectedValue();
			if(selectedStep == null) {
				return;
			}
			SessionMacroStep updated = showStepDialog(selectedStep);
			if(updated == null) {
				return;
			}
			selectedStep.setMethod(updated.getMethod());
			selectedStep.setUrl(updated.getUrl());
			selectedStep.setHeaders(updated.getHeaders());
			selectedStep.setBody(updated.getBody());
			stepList.repaint();
			persistMacros();
		}

		private void removeStep() {
			int index = stepList.getSelectedIndex();
			SessionRenewalMacro macro = macroList.getSelectedValue();
			if(index < 0 || macro == null) {
				return;
			}
			macro.getSteps().remove(index);
			stepListModel.remove(index);
			if(!stepListModel.isEmpty()) {
				stepList.setSelectedIndex(Math.min(index, stepListModel.size() - 1));
			}
			persistMacros();
		}

		private void moveStep(int delta) {
			int index = stepList.getSelectedIndex();
			SessionRenewalMacro macro = macroList.getSelectedValue();
			if(index < 0 || macro == null) {
				return;
			}
			int targetIndex = index + delta;
			if(targetIndex < 0 || targetIndex >= stepListModel.size()) {
				return;
			}
			SessionMacroStep step = stepListModel.get(index);
			stepListModel.remove(index);
			stepListModel.add(targetIndex, step);
			macro.getSteps().remove(index);
			macro.getSteps().add(targetIndex, step);
			stepList.setSelectedIndex(targetIndex);
			persistMacros();
		}

		private SessionMacroStep showStepDialog(SessionMacroStep existing) {
			JTextField methodField = new JTextField(existing != null ? existing.getMethod() : "GET");
			JTextField urlField = new JTextField(existing != null ? existing.getUrl() : "");
			PlaceholderTextArea headersArea = new PlaceholderTextArea(5, 40);
			headersArea.setPlaceholder("Header: value");
			headersArea.setText(existing != null ? existing.getHeaders() : "");
			PlaceholderTextArea bodyArea = new PlaceholderTextArea(8, 40);
			bodyArea.setPlaceholder("{\"example\":\"value\"}");
			bodyArea.setText(existing != null ? existing.getBody() : "");

			JPanel panel = new JPanel(new GridBagLayout());
			GridBagConstraints c = new GridBagConstraints();
			c.insets = new Insets(5, 5, 5, 5);
			c.fill = GridBagConstraints.HORIZONTAL;
			c.gridx = 0;
			c.gridy = 0;
			panel.add(new JLabel("HTTP Method"), c);
			c.gridx = 1;
			panel.add(methodField, c);
			c.gridx = 0;
			c.gridy++;
			panel.add(new JLabel("URL"), c);
			c.gridx = 1;
			panel.add(urlField, c);
			c.gridx = 0;
			c.gridy++;
			c.gridwidth = 2;
			panel.add(new JLabel("Headers (one per line)"), c);
			c.gridy++;
			panel.add(new JScrollPane(headersArea), c);
			c.gridy++;
			panel.add(new JLabel("Body"), c);
			c.gridy++;
			panel.add(new JScrollPane(bodyArea), c);

			int result = JOptionPane.showConfirmDialog(this, panel,
					existing == null ? "Add Macro Step" : "Edit Macro Step", JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.PLAIN_MESSAGE);
			if(result != JOptionPane.OK_OPTION) {
				return null;
			}
			String url = urlField.getText().trim();
			if(url.isEmpty()) {
				JOptionPane.showMessageDialog(this, "URL is required.", "Validation Error",
						JOptionPane.WARNING_MESSAGE);
				return null;
			}
			// Validate URL format
			try {
				new java.net.URL(url);
			} catch (java.net.MalformedURLException e) {
				JOptionPane.showMessageDialog(this, 
					"Invalid URL format: " + e.getMessage() + "\n\nPlease enter a valid URL (e.g., https://example.com/path).",
					"Invalid URL", JOptionPane.ERROR_MESSAGE);
				return null;
			}
			SessionMacroStep step = new SessionMacroStep();
			step.setMethod(methodField.getText().trim().isEmpty() ? "GET" : methodField.getText().trim());
			step.setUrl(url);
			step.setHeaders(headersArea.getText());
			step.setBody(bodyArea.getText());
			return step;
		}

		private void loadSelectedMacro() {
			loading = true;
			stepListModel.clear();
			SessionRenewalMacro macro = macroList.getSelectedValue();
			if(macro == null) {
				nameField.setText("");
				descriptionArea.setText("");
				loading = false;
				return;
			}
			nameField.setText(macro.getName());
			descriptionArea.setText(macro.getDescription());
			for(SessionMacroStep step : macro.getSteps()) {
				stepListModel.addElement(step);
			}
			loading = false;
		}

		public void reloadFromConfig() {
			loading = true;
			macroListModel.clear();
			java.util.List<SessionRenewalMacro> macros = config.getRenewalMacros();
			if(macros.isEmpty()) {
				SessionRenewalMacro macro = new SessionRenewalMacro();
				macro.setName("Default Macro");
				ArrayList<SessionRenewalMacro> newMacros = new ArrayList<>(macros);
				newMacros.add(macro);
				config.setRenewalMacros(newMacros);
				macros = config.getRenewalMacros();
			}
			for(SessionRenewalMacro macro : macros) {
				SessionRenewalMacro copy = new SessionRenewalMacro();
				copy.setId(macro.getId());
				copy.setName(macro.getName());
				copy.setDescription(macro.getDescription());
				copy.setSteps(new ArrayList<>(macro.getSteps()));
				macroListModel.addElement(copy);
			}
			if(!macroListModel.isEmpty()) {
				macroList.setSelectedIndex(0);
			}
			loading = false;
			loadSelectedMacro();
		}

		private void persistMacros() {
			if(loading) {
				return;
			}
			ArrayList<SessionRenewalMacro> macros = new ArrayList<>();
			for(int i = 0; i < macroListModel.size(); i++) {
				SessionRenewalMacro source = macroListModel.getElementAt(i);
				SessionRenewalMacro copy = new SessionRenewalMacro();
				copy.setId(source.getId());
				copy.setName(source.getName());
				copy.setDescription(source.getDescription());
				copy.setSteps(new ArrayList<>(source.getSteps()));
				macros.add(copy);
			}
			config.setRenewalMacros(macros);
			mainPanel.getConfigurationPanel().refreshSessionMacroOptions();
		}

		private static class SimpleDocumentListener implements DocumentListener {
			private final Runnable callback;
			SimpleDocumentListener(Runnable callback) {
				this.callback = callback;
			}
			@Override public void insertUpdate(DocumentEvent e) { callback.run(); }
			@Override public void removeUpdate(DocumentEvent e) { callback.run(); }
			@Override public void changedUpdate(DocumentEvent e) { callback.run(); }
		}
	}

	private static class SessionStatusPanel extends JPanel {

		private static final long serialVersionUID = 1L;
		private final JPanel rowsPanel = new JPanel(new GridBagLayout());
		private final Map<String, SessionMonitorRow> rowMap = new LinkedHashMap<>();
		private final SessionValidationManager validationManager = SessionValidationManager.getInstance();
		private final JLabel autoStatusLabel = new JLabel("Auto validation disabled");
		private final JToggleButton autoValidateToggle = new JToggleButton("Auto Validate");

		SessionStatusPanel() {
			setLayout(new BorderLayout(5, 5));
			JPanel topControls = new JPanel();
			JButton validateAllButton = new JButton("Validate All Now");
			validateAllButton.addActionListener(e -> validationManager.validateAllSessions());
			autoValidateToggle.addActionListener(e -> {
				boolean enabled = autoValidateToggle.isSelected();
				validationManager.setAutoValidationEnabled(enabled);
				updateAutoStatus();
			});
			topControls.add(validateAllButton);
			topControls.add(autoValidateToggle);
			topControls.add(autoStatusLabel);
			add(topControls, BorderLayout.NORTH);
			JScrollPane scrollPane = new JScrollPane(rowsPanel);
			add(scrollPane, BorderLayout.CENTER);
			refreshSessions();
			updateAutoStatus();
		}

		private void updateAutoStatus() {
			if(validationManager.isAutoValidationEnabled()) {
				autoStatusLabel.setText("Auto validation enabled (every "
						+ SessionValidationManager.DEFAULT_INTERVAL_SECONDS + "s)");
				autoStatusLabel.setForeground(new Color(0, 128, 0));
				autoValidateToggle.setSelected(true);
			}
			else {
				autoStatusLabel.setText("Auto validation disabled");
				autoStatusLabel.setForeground(Color.DARK_GRAY);
				autoValidateToggle.setSelected(false);
			}
		}

		public void refreshSessions() {
			SwingUtilities.invokeLater(() -> {
				rowsPanel.removeAll();
				rowMap.clear();
				GridBagConstraints c = new GridBagConstraints();
				c.gridx = 0;
				c.gridy = 0;
				c.insets = new Insets(5, 5, 5, 5);
				c.fill = GridBagConstraints.HORIZONTAL;
				for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
					SessionMonitorRow row = new SessionMonitorRow(session);
					rowMap.put(session.getName(), row);
					rowsPanel.add(row, c);
					c.gridy++;
				}
				c.weighty = 1;
				rowsPanel.add(new JPanel(), c);
				rowsPanel.revalidate();
				rowsPanel.repaint();
			});
		}

		public void updateSessionRow(Session session) {
			SwingUtilities.invokeLater(() -> {
				SessionMonitorRow row = rowMap.get(session.getName());
				if(row != null) {
					row.update(session);
				}
			});
		}

		private class SessionMonitorRow extends JPanel {

			private static final long serialVersionUID = 1L;
			private final JLabel statusLabel = new JLabel();
			private final JLabel detailsLabel = new JLabel();
			private final JLabel monitoringLabel = new JLabel();
			private final JButton validateButton = new JButton("Validate");
			private Session session;

			SessionMonitorRow(Session session) {
				this.session = session;
				setLayout(new GridBagLayout());
				setBorder(BorderFactory.createEtchedBorder());
				GridBagConstraints c = new GridBagConstraints();
				c.insets = new Insets(5,5,5,5);
				c.gridx = 0;
				add(new JLabel("<html><strong>" + session.getName() + "</strong></html>"), c);
				c.gridx = 1;
				add(monitoringLabel, c);
				c.gridx = 2;
				add(statusLabel, c);
				c.gridx = 3;
				c.weightx = 1;
				detailsLabel.putClientProperty("html.disable", null);
				add(detailsLabel, c);
				c.gridx = 4;
				c.weightx = 0;
				validateButton.addActionListener(e -> validationManager.validateSession(session));
				add(validateButton, c);
				update(session);
			}

			private void applyChipStyle(JLabel label, String text, Color fg, Color bg) {
				label.setText(text);
				label.setForeground(fg);
				label.setOpaque(true);
				label.setBackground(bg);
				label.setBorder(BorderFactory.createCompoundBorder(
					BorderFactory.createLineBorder(new Color(180,180,180)),
					new EmptyBorder(2,8,2,8)
				));
			}

			void update(Session session) {
				this.session = session;
				SessionValidationConfig config = session.getValidationConfig();
				boolean enabled = config != null && config.isEnabled();
				monitoringLabel.setText(enabled ? "Monitoring: Enabled" : "Monitoring: Disabled");
				monitoringLabel.setForeground(enabled ? new Color(0, 128, 0) : Color.DARK_GRAY);
				validateButton.setEnabled(enabled);
				SessionValidationState state = session.getValidationState();
				Color fg = Color.WHITE;
				Color bg = new Color(128,128,128);
				String chipText = state.name();
				if(state == SessionValidationState.VALID) {
					bg = new Color(0, 153, 51); // green
				}
				else if(state == SessionValidationState.EXPIRED) {
					bg = new Color(204, 0, 0); // red
				}
				else if(state == SessionValidationState.ERROR) {
					bg = new Color(230, 138, 0); // orange
				}
				else if(state == SessionValidationState.UNKNOWN) {
					bg = new Color(96, 96, 96); // gray
				}
				applyChipStyle(statusLabel, chipText, fg, bg);
				StringBuilder details = new StringBuilder("<html>");
				if(session.getLastValidationTimestamp() > 0) {
					SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
					details.append("Last check: ").append(sdf.format(new Date(session.getLastValidationTimestamp())));
				}
				if(session.getLastValidationMessage() != null && !session.getLastValidationMessage().isEmpty()) {
					if(details.length() > 6) {
						details.append("<br>");
					}
					details.append(session.getLastValidationMessage());
				}
				details.append("</html>");
				detailsLabel.setText(details.toString());
			}
		}
	}
}

