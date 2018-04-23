package mx.nic.rdap.auth.openidc.shiro;

import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.shiro.exception.RedirectException;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.EndUserToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class IdentifierFilter extends AuthenticatingFilter {

	public static final String ID_PARAM = "id";
	public static final String ID_TOKEN_PARAM = "id_token";
	public static final String ACCESS_TOKEN_PARAM = "access_token";
	
	private static Logger logger = Logger.getLogger(IdentifierFilter.class.getName());

	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		logger.log(Level.SEVERE, "At createToken");
		// Previously it has been assured that the parameter(s) exists
		if (request.getParameter(ID_PARAM) != null) {
			return new EndUserToken(request.getParameter(ID_PARAM).trim(), request);
		}
		// TODO The issuer MAY be obtained from the referer, just to know where to validate tokens
		if (request.getAttribute(Configuration.USER_INFO_ATTR) != null) {
			return new UserInfoToken(request);
		}
		if (request.getParameter(ID_TOKEN_PARAM) != null && request.getParameter(ACCESS_TOKEN_PARAM) != null) {
			return new CustomOIDCToken(request.getParameter(ID_TOKEN_PARAM).trim(),
					request.getParameter(ACCESS_TOKEN_PARAM).trim());
		}
		return null;
	}
	
	@Override
	protected boolean isPermissive(Object mappedValue) {
		// The filter is permissive by default
		return true;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		logger.log(Level.SEVERE, "At onAccessDenied = " + isLoginRequest(request, response));
		if (!isLoginRequest(request, response)) {
			return true;
		}
		return executeLogin(request, response);
	}

	@Override
	protected final boolean isLoginRequest(ServletRequest request, ServletResponse response) {
		logger.log(Level.SEVERE, "At isLoginRequest = " + hasValidParams(request));
		return hasValidParams(request);
	}

	private boolean hasValidParams(ServletRequest request) {
		Map<String, String[]> queryParams = request.getParameterMap();
		if (queryParams.containsKey(ID_PARAM)) {
			String[] idValue = queryParams.get(ID_PARAM);
			return idValue != null && idValue.length == 1 && !idValue[0].trim().isEmpty();
		}
		if (queryParams.containsKey(ID_TOKEN_PARAM) && queryParams.containsKey(ACCESS_TOKEN_PARAM)) {
			String[] idTokenValue = queryParams.get(ID_TOKEN_PARAM);
			String[] accessTokenValue = queryParams.get(ACCESS_TOKEN_PARAM);
			return (idTokenValue != null && idTokenValue.length == 1 && !idTokenValue[0].trim().isEmpty())
					&& (accessTokenValue != null && accessTokenValue.length == 1
							&& !accessTokenValue[0].trim().isEmpty());
		}
		return request.getAttribute(Configuration.USER_INFO_ATTR) != null;
	}

	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		if (e instanceof RedirectException) {
			RedirectException re = (RedirectException) e;
			try {
				((HttpServletResponse) response).sendRedirect(re.getLocation());
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return false;
			}
			return false;
		} else {
			e.printStackTrace();
		}
		return false;
	}

}
