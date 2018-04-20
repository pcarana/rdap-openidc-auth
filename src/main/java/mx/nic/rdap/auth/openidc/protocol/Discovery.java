package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class Discovery {

	private Discovery() {
		// Empty
	}
	
	public static String discoverProvider(String userId) {
		// FIXME TODO Not implemented by the library
		String providerUri = "https://accounts.google.com/";
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
