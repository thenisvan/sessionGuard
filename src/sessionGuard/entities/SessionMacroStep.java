package sessionGuard.entities;

import java.io.Serializable;

/**
 * Represents a single HTTP request inside a renewal macro. The request is stored
 * as structured fields (method, URL, headers, body) so that the UI can display
 * and edit every part easily. When the macro executes, these fields are converted
 * into a Burp HTTP message and placeholders are replaced with the current session
 * tokens/headers.
 */
public class SessionMacroStep implements Serializable {

	private static final long serialVersionUID = 1L;

	private String method = "GET";
	private String url = "";
	private String headers = "";
	private String body = "";

	public SessionMacroStep() {}

	public SessionMacroStep(String method, String url, String headers, String body) {
		this.method = method != null ? method : "GET";
		this.url = url != null ? url : "";
		this.headers = headers != null ? headers : "";
		this.body = body != null ? body : "";
	}

	public SessionMacroStep(SessionMacroStep other) {
		if(other != null) {
			this.method = other.method;
			this.url = other.url;
			this.headers = other.headers;
			this.body = other.body;
		}
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getHeaders() {
		return headers;
	}

	public void setHeaders(String headers) {
		this.headers = headers;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}
}

