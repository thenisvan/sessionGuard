package sessionGuard.util;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import sessionGuard.entities.Session;
import sessionGuard.gui.dialog.SessionRenewalFailureDialog;
import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.SessionValidationState;
import sessionGuard.entities.Token;
import sessionGuard.entities.TokenPriority;
import sessionGuard.util.ExtractionHelper;
import sessionGuard.util.RequestModifHelper;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class SessionValidationManager {

	public static final int DEFAULT_INTERVAL_SECONDS = 60;
	private static final SessionValidationManager INSTANCE = new SessionValidationManager();
	private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
	private final ExecutorService workerPool = Executors.newFixedThreadPool(2);
	private ScheduledFuture<?> scheduledTask;
	private boolean autoValidationEnabled = false;

	private SessionValidationManager() {}

	public static SessionValidationManager getInstance() {
		return INSTANCE;
	}

	public boolean isAutoValidationEnabled() {
		return autoValidationEnabled;
	}

	public synchronized void setAutoValidationEnabled(boolean enabled) {
		if(enabled && !autoValidationEnabled) {
			scheduledTask = scheduler.scheduleAtFixedRate(() -> validateAllSessions(), DEFAULT_INTERVAL_SECONDS, DEFAULT_INTERVAL_SECONDS, TimeUnit.SECONDS);
			autoValidationEnabled = true;
		}
		else if(!enabled && autoValidationEnabled) {
			if(scheduledTask != null) {
				scheduledTask.cancel(true);
			}
			autoValidationEnabled = false;
		}
	}

	public void validateAllSessions() {
		for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			validateSession(session);
		}
	}

	public void validateSession(Session session) {
		if(session == null) {
			return;
		}
		workerPool.submit(() -> performValidationInternal(session, true));
	}

	private void performValidationInternal(Session session, boolean allowRenewal) {
		SessionValidationConfig config = session.getValidationConfig();
		if(config == null || !config.isEnabled()) {
			session.setValidationState(SessionValidationState.UNKNOWN);
			session.setLastValidationMessage("Monitoring disabled.");
			notifyUi(session);
			return;
		}
		try {
			URL url = new URL(config.getTargetUrl());
			IHttpService service = buildService(url);
			byte[] baseMessage = buildBaseMessage(url, config);
			TokenPriority tokenPriority = new TokenPriority();
			byte[] modifiedRequest = RequestModifHelper.getModifiedRequest(baseMessage, session, tokenPriority);
			IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(modifiedRequest);
			byte[] requestBody = Arrays.copyOfRange(modifiedRequest, requestInfo.getBodyOffset(), modifiedRequest.length);
			List<String> headers = RequestModifHelper.getModifiedHeaders(requestInfo.getHeaders(), session);
			byte[] finalMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, requestBody);
			IHttpRequestResponse response = BurpExtender.callbacks.makeHttpRequest(service, finalMessage);
			if(response == null || response.getResponse() == null) {
				setError(session, "No response received.");
				return;
			}
			IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(response.getResponse());
			byte[] responseBytes = response.getResponse();
			byte[] responseBodyBytes = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);
			String responseBody = new String(responseBodyBytes, StandardCharsets.UTF_8);
			boolean statusMatch = responseInfo.getStatusCode() == config.getExpectedStatusCode();
			boolean bodyMatch = true;
			if(config.isUseRegex() && config.getExpectedBodyRegex() != null && !config.getExpectedBodyRegex().isEmpty()) {
				bodyMatch = Pattern.compile(config.getExpectedBodyRegex(), Pattern.DOTALL).matcher(responseBody).find();
			}
			else if(config.getExpectedBodySubstring() != null && !config.getExpectedBodySubstring().isEmpty()) {
				bodyMatch = responseBody.contains(config.getExpectedBodySubstring());
			}

			if(statusMatch && bodyMatch) {
				session.resetRenewalFailureCount();
				session.setValidationState(SessionValidationState.VALID);
				session.setLastValidationMessage("Session healthy (HTTP " + responseInfo.getStatusCode() + ").");
			}
			else {
				session.setValidationState(SessionValidationState.EXPIRED);
				StringBuilder msg = new StringBuilder("Validation failed: ");
				if(!statusMatch) {
					msg.append("Expected ").append(config.getExpectedStatusCode()).append(", got ").append(responseInfo.getStatusCode()).append(". ");
				}
				if(!bodyMatch) {
					msg.append("Response body mismatch.");
				}
				session.setLastValidationMessage(msg.toString().trim());
				if(allowRenewal) {
					handleExpiredSession(session);
					return;
				}
			}
			session.setLastValidationTimestamp(System.currentTimeMillis());
			extractTokensFromResponse(session, response, tokenPriority);
			notifyUi(session);
		}
		catch (Exception e) {
			setError(session, "Validation error: " + e.getMessage());
		}
	}

	private IHttpService buildService(URL url) {
		int port = url.getPort();
		if(port == -1) {
			port = url.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
		}
		return BurpExtender.callbacks.getHelpers().buildHttpService(url.getHost(), port, url.getProtocol());
	}

	private byte[] buildBaseMessage(URL url, SessionValidationConfig config) {
		String path = url.getFile();
		if(path == null || path.isEmpty()) {
			path = "/";
		}
		List<String> headers = new ArrayList<String>();
		headers.add(config.getHttpMethod() + " " + path + " HTTP/1.1");
		String hostHeader = url.getPort() == -1 ? url.getHost() : url.getHost() + ":" + url.getPort();
		headers.add("Host: " + hostHeader);
		headers.add("User-Agent: AuthAnalyzer-SessionMonitor");
		headers.add("Accept: */*");
		headers.add("Connection: close");
		if(config.getRequestHeaders() != null) {
			String[] additionalHeaders = config.getRequestHeaders().replace("\r", "").split("\n");
			for(String header : additionalHeaders) {
				String trimmed = header.trim();
				if(!trimmed.isEmpty()) {
					headers.add(trimmed);
				}
			}
		}
		String body = config.getRequestBody() != null ? config.getRequestBody() : "";
		return BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body.getBytes(StandardCharsets.UTF_8));
	}

	public static void extractTokensFromResponse(Session session, IHttpRequestResponse response, TokenPriority tokenPriority) {
		IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(response.getResponse());
		for (Token token : session.getTokens()) {
			boolean success = false;
			if (token.isAutoExtract()) {
				success = ExtractionHelper.extractCurrentTokenValue(response.getResponse(), responseInfo, token);
			}
			if (token.isFromToString()) {
				success = ExtractionHelper.extractTokenWithFromToString(response.getResponse(), responseInfo, token);
			}
			if(success) {
				session.getStatusPanel().updateTokenStatus(token);
				if(token.getRequestResponse() == null || token.getPriority() <= tokenPriority.getPriority()) {
					token.setRequestResponse(response);
					token.setPriority(tokenPriority.getPriority());
				}
			}
		}
	}

	private void setError(Session session, String message) {
		session.setValidationState(SessionValidationState.ERROR);
		session.setLastValidationTimestamp(System.currentTimeMillis());
		session.setLastValidationMessage(message);
		notifyUi(session);
	}

	private void notifyUi(Session session) {
		SwingUtilities.invokeLater(() -> {
			BurpExtender.mainPanel.getConfigurationPanel().updateSessionValidationVisuals(session);
		});
	}

	private void handleExpiredSession(Session session) {
		SessionValidationConfig config = session.getValidationConfig();
		if(config == null || config.getRenewalMacroName() == null || config.getRenewalMacroName().isEmpty()) {
			session.setLastValidationTimestamp(System.currentTimeMillis());
			notifyUi(session);
			return;
		}
		boolean renewed = SessionMacroExecutor.execute(session);
		if(renewed) {
			session.resetRenewalFailureCount();
			performValidationInternal(session, false);
		}
		else {
			session.incrementRenewalFailureCount();
			session.setLastValidationTimestamp(System.currentTimeMillis());
			session.setLastValidationMessage("Renewal failed (" + session.getRenewalFailureCount() + " attempt(s)).");
			notifyUi(session);
			if(session.getRenewalFailureCount() >= 3) {
				SessionRenewalFailureDialog.show(session.getName());
			}
		}
	}
}

