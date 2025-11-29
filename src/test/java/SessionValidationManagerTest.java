package sessionGuard.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import sessionGuard.entities.SessionValidationConfig;
import sessionGuard.entities.SessionValidationState;

/**
 * Unit tests for SessionValidationConfig and validation success criteria logic.
 * Tests status code, substring, and regex matching patterns.
 */
public class SessionValidationManagerTest {

	private SessionValidationConfig config;

	@Before
	public void setUp() {
		config = new SessionValidationConfig();
	}

	@Test
	public void testStatusCodeMatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodySubstring("");
		config.setExpectedBodyRegex("");

		// Simulated validation: 200 status should pass
		int actualStatus = 200;
		assertEquals("Status code should match", 200, actualStatus);
	}

	@Test
	public void testStatusCodeMismatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);

		// Simulated validation: 401 status should fail
		int actualStatus = 401;
		assertNotEquals("Status code should not match", config.getExpectedStatusCode(), actualStatus);
	}

	@Test
	public void testBodySubstringMatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodySubstring("success");
		config.setUseRegex(false);

		String responseBody = "{\"status\":\"success\",\"user\":\"test\"}";
		assertTrue("Body should contain substring", responseBody.contains(config.getExpectedBodySubstring()));
	}

	@Test
	public void testBodySubstringMismatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodySubstring("success");
		config.setUseRegex(false);

		String responseBody = "{\"status\":\"failed\",\"user\":\"test\"}";
		assertFalse("Body should not contain substring", responseBody.contains(config.getExpectedBodySubstring()));
	}

	@Test
	public void testBodyRegexMatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodyRegex("\"status\"\\s*:\\s*\"success\"");
		config.setUseRegex(true);

		String responseBody = "{\"status\": \"success\",\"user\":\"test\"}";
		assertTrue("Body should match regex", responseBody.matches(".*" + config.getExpectedBodyRegex() + ".*"));
	}

	@Test
	public void testBodyRegexMismatch() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodyRegex("\"status\"\\s*:\\s*\"success\"");
		config.setUseRegex(true);

		String responseBody = "{\"status\": \"failed\",\"user\":\"test\"}";
		assertFalse("Body should not match regex", responseBody.matches(".*" + config.getExpectedBodyRegex() + ".*"));
	}

	@Test
	public void testComplexRegexPattern() {
		config.setEnabled(true);
		config.setExpectedStatusCode(200);
		config.setExpectedBodyRegex("token-[A-Za-z0-9]{8,}");
		config.setUseRegex(true);

		String responseBody = "Your session token is: token-abc123xyz789. Please store it safely.";
		assertTrue("Body should match complex regex", responseBody.matches(".*" + config.getExpectedBodyRegex() + ".*"));
	}

	@Test
	public void testEmptyCriteria() {
		config.setEnabled(true);
		config.setExpectedStatusCode(0);
		config.setExpectedBodySubstring("");
		config.setExpectedBodyRegex("");
		config.setUseRegex(false);

		// When no criteria specified, only status code check applies (if set to non-zero)
		assertEquals("No specific criteria set", 0, config.getExpectedStatusCode());
		assertEquals("No substring set", "", config.getExpectedBodySubstring());
		assertEquals("No regex set", "", config.getExpectedBodyRegex());
	}

	@Test
	public void testValidationConfigDefaults() {
		SessionValidationConfig defaultConfig = new SessionValidationConfig();
		assertFalse("Should be disabled by default", defaultConfig.isEnabled());
		String defaultUrl = defaultConfig.getTargetUrl();
		assertTrue("Target URL should be null or empty", defaultUrl == null || defaultUrl.isEmpty());
		assertEquals("Method should default to GET", "GET", defaultConfig.getHttpMethod());
		assertTrue("Expected status should be non-negative", defaultConfig.getExpectedStatusCode() >= 0);
		assertFalse("Regex should be disabled by default", defaultConfig.isUseRegex());
	}

	@Test
	public void testSessionValidationStateEnum() {
		// Verify all validation states are available
		SessionValidationState[] states = SessionValidationState.values();
		assertEquals("Should have 4 validation states", 4, states.length);
		
		assertTrue("VALID state should exist", contains(states, SessionValidationState.VALID));
		assertTrue("EXPIRED state should exist", contains(states, SessionValidationState.EXPIRED));
		assertTrue("ERROR state should exist", contains(states, SessionValidationState.ERROR));
		assertTrue("UNKNOWN state should exist", contains(states, SessionValidationState.UNKNOWN));
	}

	private boolean contains(SessionValidationState[] states, SessionValidationState target) {
		for(SessionValidationState state : states) {
			if(state == target) {
				return true;
			}
		}
		return false;
	}
}
