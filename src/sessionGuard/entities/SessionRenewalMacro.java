package sessionGuard.entities;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Named macro that can be referenced by one or more sessions. Contains a
 * user-friendly name/description and the ordered macro steps.
 */
public class SessionRenewalMacro implements Serializable {

	private static final long serialVersionUID = 1L;

	private String id = UUID.randomUUID().toString();
	private String name = "Macro";
	private String description = "";
	private final List<SessionMacroStep> steps = new ArrayList<>();

	public SessionRenewalMacro() {}

	public SessionRenewalMacro(String name) {
		this.name = name;
	}

	public SessionRenewalMacro(SessionRenewalMacro other) {
		if(other != null) {
			this.id = other.id;
			this.name = other.name;
			this.description = other.description;
			for(SessionMacroStep step : other.steps) {
				this.steps.add(new SessionMacroStep(step));
			}
		}
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public List<SessionMacroStep> getSteps() {
		return steps;
	}

	public void setSteps(List<SessionMacroStep> newSteps) {
		this.steps.clear();
		if(newSteps != null) {
			for(SessionMacroStep step : newSteps) {
				this.steps.add(new SessionMacroStep(step));
			}
		}
	}

	public SessionMacroStep getStep(int index) {
		return steps.get(index);
	}

	public void addStep(SessionMacroStep step) {
		if(step != null) {
			steps.add(step);
		}
	}

	public void removeStep(int index) {
		if(index >= 0 && index < steps.size()) {
			steps.remove(index);
		}
	}
}

