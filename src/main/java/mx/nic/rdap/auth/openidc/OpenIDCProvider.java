package mx.nic.rdap.auth.openidc;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class OpenIDCProvider {

	private String id;
	private String secret;
	private String callbackURI;
	private String providerURI;
	private OIDCProviderMetadata metadata;
	
	public OpenIDCProvider() {
		// Empty
	}
	
	public OpenIDCProvider(String id, String secret, String callbackURI, String providerURI) {
		this.id = id;
		this.secret = secret;
		this.callbackURI = callbackURI;
		this.providerURI = providerURI;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public String getCallbackURI() {
		return callbackURI;
	}

	public void setCallbackURI(String callbackURI) {
		this.callbackURI = callbackURI;
	}

	public String getProviderURI() {
		return providerURI;
	}

	public void setProviderURI(String providerURI) {
		this.providerURI = providerURI;
	}

	public OIDCProviderMetadata getMetadata() {
		return metadata;
	}

	public void setMetadata(OIDCProviderMetadata metadata) {
		this.metadata = metadata;
	}

}
