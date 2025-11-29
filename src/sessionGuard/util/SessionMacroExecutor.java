package sessionGuard.util;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import sessionGuard.entities.Session;
import sessionGuard.entities.SessionMacroStep;
import sessionGuard.entities.SessionRenewalMacro;
import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.Token;
import sessionGuard.entities.TokenPriority;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

/**
 * Executes the renewal macro configured for a session. Each macro step is
 * replayed with placeholders resolved through the existing RequestModifHelper.
 */
public class SessionMacroExecutor {

	private SessionMacroExecutor() {}

	public static boolean execute(Session session) {
		if(session == null) {
			return false;
		}
		SessionValidationConfig config = session.getValidationConfig();
		if(config == null) {
			return false;
		}
		List<SessionMacroStep> steps = resolveSteps(config);
		if(steps.isEmpty()) {
			return false;
		}
		try {
			for(SessionMacroStep step : steps) {
				if(!executeStep(session, step)) {
					return false;
				}
			}
			return true;
		}
		catch (Exception e) {
			BurpExtender.callbacks.printError("Macro execution failed: " + e.getMessage());
			return false;
		}
	}

	private static List<SessionMacroStep> resolveSteps(SessionValidationConfig config) {
		List<SessionMacroStep> steps = new ArrayList<>();
		String macroName = config.getRenewalMacroName();
		if(macroName == null || macroName.isEmpty()) {
			return steps;
		}
		SessionRenewalMacro macro = CurrentConfig.getCurrentConfig().getRenewalMacroByName(macroName);
		if(macro == null || macro.getSteps().isEmpty()) {
			return steps;
		}
		for(SessionMacroStep step : macro.getSteps()) {
			steps.add(new SessionMacroStep(step));
		}
		return steps;
	}

	private static boolean executeStep(Session session, SessionMacroStep step) throws Exception {
		if(step.getUrl() == null || step.getUrl().isEmpty()) {
			BurpExtender.callbacks.printError("Macro step execution failed: URL is empty.");
			return false;
		}
		URL url = new URL(step.getUrl());
		String method = step.getMethod() != null && !step.getMethod().isEmpty() ? step.getMethod() : "GET";
		String path = url.getFile();
		if(path == null || path.isEmpty()) {
			path = "/";
		}
		List<String> headers = new ArrayList<>();
		headers.add(method + " " + path + " HTTP/1.1");
		String hostHeader = url.getHost();
		int port = url.getPort();
		if(port != -1 && port != 80 && port != 443) {
			hostHeader = hostHeader + ":" + port;
		}
		boolean hasHost = false;
		if(step.getHeaders() != null && !step.getHeaders().isEmpty()) {
			for(String headerLine : step.getHeaders().replace("\r", "").split("\n")) {
				String trimmed = headerLine.trim();
				if(trimmed.isEmpty()) {
					continue;
				}
				if(trimmed.toLowerCase().startsWith("host:")) {
					hasHost = true;
				}
				headers.add(trimmed);
			}
		}
		if(!hasHost) {
			headers.add(1, "Host: " + hostHeader);
		}

		// Replace placeholders in headers
		headers = replacePlaceholders(headers, session);

		// Replace placeholders in body
		String bodyText = step.getBody() != null ? replacePlaceholders(step.getBody(), session) : "";
		byte[] body = bodyText.getBytes(StandardCharsets.UTF_8);
		byte[] baseMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);
		TokenPriority tokenPriority = new TokenPriority();
		byte[] modifiedRequest = RequestModifHelper.getModifiedRequest(baseMessage, session, tokenPriority);
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(modifiedRequest);
		byte[] requestBody = Arrays.copyOfRange(modifiedRequest, requestInfo.getBodyOffset(), modifiedRequest.length);
		List<String> finalHeaders = RequestModifHelper.getModifiedHeaders(requestInfo.getHeaders(), session);
		byte[] finalMessage = BurpExtender.callbacks.getHelpers().buildHttpMessage(finalHeaders, requestBody);

		int servicePort = port;
		if(servicePort == -1) {
			servicePort = url.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
		}
		IHttpService service = BurpExtender.callbacks.getHelpers().buildHttpService(url.getHost(), servicePort,
				url.getProtocol());
		IHttpRequestResponse response = BurpExtender.callbacks.makeHttpRequest(service, finalMessage);
		if(response == null) {
			BurpExtender.callbacks.printError("Macro step execution failed: makeHttpRequest returned null for '" + step.getUrl() + "'.");
			return false;
		}
		if(response.getResponse() == null) {
			BurpExtender.callbacks.printError("Macro step execution failed: received no response from '" + step.getUrl() + "'.");
			return false;
		}
		SessionValidationManager.extractTokensFromResponse(session, response, tokenPriority);
		return true;
	}

	/**
	 * Replaces {{tokenName}} placeholders with current token values from the session.
	 * If a token is not found or has no value, the placeholder is left unchanged.
	 */
	private static String replacePlaceholders(String text, Session session) {
		if(text == null || text.isEmpty() || session == null) {
			return text;
		}
		String result = text;
		for(Token token : session.getTokens()) {
			String tokenName = token.getName();
			String tokenValue = token.getValue();
			if(tokenName != null && !tokenName.isEmpty() && tokenValue != null && !tokenValue.isEmpty()) {
				String placeholder = "{{" + tokenName + "}}";
				result = result.replace(placeholder, tokenValue);
			}
		}
		return result;
	}

	/**
	 * Replaces {{tokenName}} placeholders in a list of header strings.
	 */
	private static List<String> replacePlaceholders(List<String> headers, Session session) {
		if(headers == null || headers.isEmpty()) {
			return headers;
		}
		List<String> result = new ArrayList<>();
		for(String header : headers) {
			result.add(replacePlaceholders(header, session));
		}
		return result;
	}
}

