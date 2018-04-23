package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import mx.nic.rdap.auth.openidc.Configuration;

public class Discovery {

	private Discovery() {
		// Empty
	}
	
	public static String discoverProvider(String userId) {
		// FIXME Not implemented by the library, use manually configured URI
		String providerUri = Configuration.getProvider().getProviderURI();
		return providerUri;
	}
	
	public static OIDCProviderMetadata getProviderMetadata(String providerURI) {
		// FIXME TODO Not implemented by the library
		Issuer issuer = new Issuer(providerURI);
		OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = request.toHTTPRequest().send();
		} catch (IOException e) {
			//FIXME 
			e.printStackTrace();
			return null;
		}
		if (!httpResponse.indicatesSuccess()) {
			
		}
		try {
			return OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

}
