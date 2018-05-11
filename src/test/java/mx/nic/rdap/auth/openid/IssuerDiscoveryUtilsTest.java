package mx.nic.rdap.auth.openid;

import java.net.URISyntaxException;

import org.junit.Test;

import mx.nic.rdap.auth.openidc.protocol.IssuerDiscoveryUtils;
import mx.nic.rdap.auth.openidc.protocol.WebFingerRequest;

public class IssuerDiscoveryUtilsTest {

	@Test
	public void test() {
		get("joe@example.com");
		get("https://example.com/joe");
		get("example.com:8080");
		get("acct:juliet%40capulet.example@shopping.example.com");
	}

	public void get(String uri) {
		try {
			WebFingerRequest webFingerRequest = IssuerDiscoveryUtils.getWebFingerRequest(uri);

			System.out.println("========================");
			System.out.println("UserId Received: " + uri);
			System.out.println("resource: " + webFingerRequest.getResource());
			System.out.println("Host: " + webFingerRequest.getHost());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}

}
