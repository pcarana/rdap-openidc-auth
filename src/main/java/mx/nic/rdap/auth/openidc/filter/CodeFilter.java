package mx.nic.rdap.auth.openidc.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.exception.ResponseException;

/**
 * Specific filter used to parse an authorization code sent by an OP, the
 * request MUST contain 2 parameters "state" and "code", any other parameter
 * will be ignored.
 *
 */
public class CodeFilter implements Filter {

	private static final String STATE_PARAM = "state";
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// Get the request, the state MUST be present to forward the request
		if (request.getParameter(STATE_PARAM) == null) {
			chain.doFilter(request, response);
			return;
		}
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String forwardURI = null;
			if (request.getParameter(STATE_PARAM) != null) {
				forwardURI = new Base64(httpRequest.getParameter(STATE_PARAM)).decodeToString();
			} else {
				// FIXME Where to go?
				forwardURI = "";
			}
			UserInfo userInfo = null;
			try {
				userInfo = AuthenticationFlow.getUserInfoFromAuthCode(httpRequest.getQueryString(), Configuration.getProvider());
			} catch (Exception e) {
				// FIXME Translate to HTTP Codes, a 500 isn't too good
				if (e instanceof ResponseException) {
					ResponseException responseExc = (ResponseException) e;
					((HttpServletResponse) response).setStatus(responseExc.getCode());
				}
				throw new ServletException(e);
			}
			request.setAttribute(Configuration.USER_INFO_ATTR, userInfo);
			request.getRequestDispatcher(forwardURI).forward(request, response);
			return;
		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() { }

}
