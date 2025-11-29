package sessionGuard.entities;

import java.io.Serializable;

/**
 * Holds configuration required to validate if a session is still valid.
 * Users can define a probe request together with success criteria (status code,
 * substring, regex). Additional criteria can be added later without touching
 * the session entity again.
 */
public class SessionValidationConfig implements Serializable {

	private static final long serialVersionUID = 1L;

	private boolean enabled = false;
	private String targetUrl = "";
	private String httpMethod = "GET";
	private String requestHeaders = "";
	private String requestBody = "";
	private int expectedStatusCode = 200;
	private String expectedBodySubstring = "";
	private String expectedBodyRegex = "";
	private boolean useRegex = false;
	private String renewalMacroName = "";

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getTargetUrl() {
		return targetUrl;
	}

	public void setTargetUrl(String targetUrl) {
		this.targetUrl = targetUrl;
	}

	public String getHttpMethod() {
		return httpMethod;
	}

	public void setHttpMethod(String httpMethod) {
		this.httpMethod = httpMethod;
	}

	public String getRequestHeaders() {
		return requestHeaders;
	}

	public void setRequestHeaders(String requestHeaders) {
		this.requestHeaders = requestHeaders;
	}

	public String getRequestBody() {
		return requestBody;
	}

	public void setRequestBody(String requestBody) {
		this.requestBody = requestBody;
	}

	public int getExpectedStatusCode() {
		return expectedStatusCode;
	}

	public void setExpectedStatusCode(int expectedStatusCode) {
		this.expectedStatusCode = expectedStatusCode;
	}

	public String getExpectedBodySubstring() {
		return expectedBodySubstring;
	}

	public void setExpectedBodySubstring(String expectedBodySubstring) {
		this.expectedBodySubstring = expectedBodySubstring;
	}

	public String getExpectedBodyRegex() {
		return expectedBodyRegex;
	}

	public void setExpectedBodyRegex(String expectedBodyRegex) {
		this.expectedBodyRegex = expectedBodyRegex;
	}

	public boolean isUseRegex() {
		return useRegex;
	}

	public void setUseRegex(boolean useRegex) {
		this.useRegex = useRegex;
	}

	public String getRenewalMacroName() {
		return renewalMacroName;
	}

	public void setRenewalMacroName(String renewalMacroName) {
		this.renewalMacroName = renewalMacroName;
	}
}

