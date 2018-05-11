package mx.nic.rdap.auth.openidc.protocol;

public class WebFingerRequest {

	private String resource;
	private String host;

	public WebFingerRequest(String resource, String host) {
		super();
		this.resource = resource;
		this.host = host;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getResource() {
		return resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
	}
}
