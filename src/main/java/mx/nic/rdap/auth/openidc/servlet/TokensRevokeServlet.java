package mx.nic.rdap.auth.openidc.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import net.minidev.json.JSONObject;

/**
 * Access and refresh tokens can be revoked as described in RFC 7009 [RFC7009]
 * by sending a request to an RDAP server that contains a "tokens/revoke" path
 * segment and two query parameters. The first query parameter includes a key
 * value of "id" and a value component that contains the client identifier
 * issued by an OP. The second query parameter includes a key value of "token"
 * and a Base64url-encoded value that represents either the current refresh
 * token or the associated access token. An example:
 * 
 * https://example.com/rdap/tokens/revoke?id=user.idp.example &token=f735...d30c
 *
 * 
 */
@WebServlet(name = "TokensRevoke", urlPatterns = { "/tokens/revoke" })
public class TokensRevokeServlet extends HttpServlet {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -3755516672887712201L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String parameter = sanitizeParameter(request.getParameter("id"));
		String token = sanitizeParameter(request.getParameter("token"));

		if (parameter == null || token == null) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "empty or null id and/or token parameters.");
			return;
		}

		try {
			token = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
		} catch (IllegalArgumentException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
			return;
		}

		JSONObject tokenRevokeJSON = null;
		try {
			tokenRevokeJSON = AuthenticationFlow.getTokenRevokeJSON(token, Configuration.getProvider());
		} catch (RequestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ResponseException e) {
			response.sendError(e.getCode(), e.getMessage());
			return;
		}

		response.setContentType("application/json");
		if (tokenRevokeJSON != null && !tokenRevokeJSON.isEmpty()) {
			boolean containsKey = tokenRevokeJSON.containsKey("error");
			if (containsKey) {
				writeJsonErrorResponse(response, tokenRevokeJSON);
				return;
			}
			
			response.getOutputStream().print(tokenRevokeJSON.toString());
			response.getOutputStream().flush();
		} else {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}
		return;

	}

	private void writeJsonErrorResponse(HttpServletResponse response, JSONObject errorJson) throws IOException {
		PrintWriter writer = response.getWriter();
		writer.write("{\"rdapConformance\":[\"rdap_level_0\",\"rdap_openidc_level_0\"],");
		writer.write("\"notices\":[{\"title\":\"");
		writer.write("Token Revocation Result");
		writer.write("\",\"description\":\"");
		writer.write("Token revocation failed.");
		if (errorJson.containsKey("error_description")) {
			writer.write(", " + errorJson.getAsString("error_description"));
		}
		if (errorJson.containsKey("error")) {
			writer.write("\",}],\"errorCode\":");
			writer.write("" + errorJson.getAsString("error"));
		} else {
			writer.write("\",}]");
		}
		writer.write(",\"lang\":\"en-US\"}");

		writer.flush();
	}

	private String sanitizeParameter(String parameter) {
		if (parameter == null) {
			return null;
		}

		parameter = parameter.trim();
		if (parameter.isEmpty()) {
			return null;
		}

		return parameter;
	}

}
