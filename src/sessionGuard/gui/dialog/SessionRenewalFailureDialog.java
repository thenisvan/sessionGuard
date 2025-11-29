package sessionGuard.gui.dialog;

import javax.swing.JOptionPane;

import sessionGuard.util.GenericHelper;

public class SessionRenewalFailureDialog {

	private SessionRenewalFailureDialog() {}

	public static void show(String sessionName) {
		JOptionPane.showMessageDialog(GenericHelper.getBurpFrame(),
				"Session \"" + sessionName + "\" could not be renewed automatically.\n"
				+ "Please update the session headers/cookies manually.",
				"Session Renewal Failed",
				JOptionPane.WARNING_MESSAGE);
	}
}

