/**
* Licensed to the Apache Software Foundation (ASF) under one
* or more contributor license agreements.  See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership.  The ASF licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.apache.hadoop.security.tokenauth.web;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AbstractAuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;
import org.apache.hadoop.security.tokenauth.api.web.WEBParams;
import org.apache.hadoop.security.tokenauth.api.web.WebHelper;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.login.TokenAuthLoginModule;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenPrincipal;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * We should consider client login using web browser and java
 * 
 */
public class TokenAuthAuthenticationHandler extends AbstractAuthenticationHandler {
  private static Logger LOG = LoggerFactory.getLogger(TokenAuthAuthenticationHandler.class);
  
  private static class TokenAuthConfiguration extends Configuration {
    private String authnFile;
    private String principal;

    public TokenAuthConfiguration(String authnFile, String principal) {
      this.authnFile = authnFile;
      this.principal = principal;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      Map<String, String> options = new HashMap<String, String>();
      
      options.put("authnFile", authnFile);
      options.put("principal", principal);
      options.put("useAuthnFile", "true");
      options.put("doNotPrompt", "true");
      options.put("useTokenCache", "false");
      options.put("renewToken", "false");

      return new AppConfigurationEntry[]{new AppConfigurationEntry(TokenAuthLoginModule.class.getName(),
          AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options),};
    }
  }
  
  /**
   * Constant that identifies the authentication mechanism.
   */
  public static final String TYPE = "tokenauth";
  /**
   * Constant for the configuration property that indicates the tokenauth principal.
   */
  public static final String PRINCIPAL = TYPE + ".principal";
  /**
   * Constant for the configuration property that indicates the authn file path.
   */
  public static final String AUTHNFILE = TYPE + ".authnfile";

  public static final String IDENTITY_HTTP_SERVER = TYPE + ".identity.server.http-address";
  
  public static final String AUTHORIZATION_HTTP_SERVER = TYPE + ".authorization.server.http-address";
  
  public static final String HTTP_SECURED = TYPE + ".http.secured";

  /**
   * Constant for the configuration property that indicates the domain to use in the HTTP cookie.
   */
  public static final String COOKIE_DOMAIN = "cookie.domain";

  /**
   * Constant for the configuration property that indicates the path to use in the HTTP cookie.
   */
  public static final String COOKIE_PATH = "cookie.path";
  
  /**
   * Constant for the configuration property that indicates which user agents
   * are not considered browsers (comma separated)
   */
  public static final String NON_BROWSER_USER_AGENTS =
          TYPE + ".non-browser.user-agents";
  private static final String NON_BROWSER_USER_AGENTS_DEFAULT =
          "java,curl,wget,perl";

  private String[] nonBrowserUserAgents;
  
  private String principal;
  private String authnFile;
  private String identityServer;
  private String authorizationServer;
  private boolean isHttpSecured = false;
  private Token identityToken;
  private Secrets validationSecrets;
  private String cookieDomain;
  private String cookiePath;
  private LoginContext loginContext;
  private HASClient hasClient;

  @Override
  public String getType() {
    return TYPE;
  }

  @Override
  public void init(Properties config) throws ServletException {
    
    nonBrowserUserAgents = config.getProperty(
        NON_BROWSER_USER_AGENTS, NON_BROWSER_USER_AGENTS_DEFAULT)
        .split("\\W*,\\W*");
    for (int i = 0; i < nonBrowserUserAgents.length; i++) {
      nonBrowserUserAgents[i] = nonBrowserUserAgents[i].toLowerCase();
    }

    try {
      identityServer = config.getProperty(IDENTITY_HTTP_SERVER, identityServer);
      authorizationServer = config.getProperty(IDENTITY_HTTP_SERVER, authorizationServer);
      String httpSecured = config.getProperty(HTTP_SECURED, "false");
      if (httpSecured.equalsIgnoreCase("true"))
        isHttpSecured = true;

      principal = config.getProperty(PRINCIPAL, principal);
      if (principal == null || principal.trim().length() == 0) {
        throw new ServletException("Principal not defined in configuration");
      }
      LOG.info("Initialize tokenauth authentication handler for " + principal);
      
      authnFile = config.getProperty(AUTHNFILE, authnFile);
      if (authnFile == null || authnFile.trim().length() == 0) {
        throw new ServletException("authn file not defined in configuration");
      }
      if (!new File(authnFile).exists()) {
        throw new ServletException("authn file does not exist: " + authnFile);
      }
      
      cookieDomain = config.getProperty(COOKIE_DOMAIN, null);
      cookiePath = config.getProperty(COOKIE_PATH, null);
      
      hasClient = new HASClientImpl(getHttpServerUrl(isHttpSecured, identityServer), 
          getHttpServerUrl(isHttpSecured, authorizationServer));
      
      Set<Principal> principals = new HashSet<Principal>();
      principals.add(new TokenPrincipal(principal));
      Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

      TokenAuthConfiguration tokenAuthConfiguration = new TokenAuthConfiguration(authnFile, principal);

      LOG.info("Login using authnFile "+authnFile+", for principal "+principal);
      loginContext = new LoginContext("", subject, new DefaultHASClientCallbackHandler(hasClient), tokenAuthConfiguration);
      loginContext.login();
      
      this.identityToken = subject.getPrivateCredentials(
          org.apache.hadoop.security.tokenauth.token.Token.class)
          .iterator().next();
      this.validationSecrets = subject.getPrivateCredentials(
          Secrets.class).isEmpty() ? null : subject.getPrivateCredentials(
          Secrets.class).iterator().next();
      
    } catch (Exception e) {
      throw new ServletException(e);
    }
  }

  @Override
  public void destroy() {
    try {
      if (loginContext != null) {
        loginContext.logout();
        loginContext = null;
      }
    } catch (LoginException ex) {
      LOG.warn(ex.getMessage(), ex);
    }
  }
  
  protected boolean isBrowser(String userAgent) {
    if (userAgent == null) {
      return false;
    }
    userAgent = userAgent.toLowerCase();
    boolean isBrowser = true;
    for (String nonBrowserUserAgent : nonBrowserUserAgents) {
        if (userAgent.contains(nonBrowserUserAgent)) {
            isBrowser = false;
            break;
        }
    }
    return isBrowser;
  }

  @Override
  public boolean managementOperation(AuthenticationToken token,
      HttpServletRequest request, HttpServletResponse response)
      throws IOException, AuthenticationException {
    return true;
  }
  
  private String getRequestFullUrl(HttpServletRequest request) {
    StringBuffer urlBuffer = new StringBuffer();
    String scheme = request.getScheme();
    String serverName = request.getServerName();
    int port = request.getServerPort();
    String requestURI = request.getRequestURI();
    String queryString = request.getQueryString();
    
    urlBuffer.append(scheme)
        .append("://").append(serverName);
    if (!(scheme.equals("http") && port == 80) ||
        (scheme.equals("https") && port == 443)) {
      urlBuffer.append(":").append(port); 
    }
    
    urlBuffer.append(requestURI);
    if (queryString != null) {
      urlBuffer.append("?").append(queryString);
    }
    return urlBuffer.toString();
  }
  
  @Override
  public boolean shouldDoAuthentication(HttpServletRequest request)
      throws IOException, AuthenticationException {
    
    String accessToken = WebHelper.getAccessTokenFromCookie(request);
    if (accessToken == null) {
      return true;
    }
    
    Token token = TokenFactory.get().createAccessToken(
        validationSecrets, TokenUtils.decodeToken(accessToken));
    if(System.currentTimeMillis() >= token.getExpiryTime()) {
      return true;
    }
    return false;
  }

  @Override
  public AuthenticationToken authenticate(HttpServletRequest httpRequest,
      HttpServletResponse httpResponse) throws IOException, AuthenticationException {
    if (isBrowser(httpRequest.getHeader("User-Agent"))) {
      String accessToken = WebHelper.getAccessTokenFromCookie(httpRequest);
      if (accessToken != null) {
        Token token = TokenFactory.get().createAccessToken(
            validationSecrets, TokenUtils.decodeToken(accessToken));
        
        String userName = token.getPrincipal().getName(); 
        return new AuthenticationToken(userName, userName, getType());
      }
      
      accessToken = httpRequest.getParameter(WEBParams.ACCESS_TOKEN_PRARM);
      if (accessToken == null) {
        //do authentication
        LOG.info("Authentication with identity server.");
        String url = getHttpServerUrl(isHttpSecured, identityServer) + WEBParams.AUTHENTICATE_SERVLET_PATH_SPEC;
        httpResponse.sendRedirect(url + "?" + 
            WEBParams.PROTOCOL_PARAM + "=" + 
            identityToken.getPrincipal().getName() + 
            "&" + WEBParams.RELAYSTATE_PARAM + "=" + 
            URLEncoder.encode(getRequestFullUrl(httpRequest), "UTF-8"));
        return null;
      }
      
      WebHelper.addAccessTokenToCookie(httpResponse, accessToken, cookieDomain, cookiePath);
      String relayState = httpRequest.getParameter(WEBParams.RELAYSTATE_PARAM);
      httpResponse.sendRedirect(relayState);
      
      return null;
    } else {
      String authorization = httpRequest.getHeader(TokenAuthAuthenticator.AUTHORIZATION);

      if (authorization == null || !authorization.startsWith(TokenAuthAuthenticator.NEGOTIATE)) {
        httpResponse.setHeader(TokenAuthAuthenticator.WWW_AUTHENTICATE, 
                               TokenAuthAuthenticator.NEGOTIATE + " " + 
                               identityToken.getPrincipal().getName());
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        if (authorization == null) {
          LOG.trace("TokenAuth starting");
        } else {
          LOG.warn("'" + TokenAuthAuthenticator.AUTHORIZATION + "' does not start with '" +
              TokenAuthAuthenticator.NEGOTIATE + "' :  {}", authorization);
        }
        
        return null;
      } else {
        authorization = authorization.substring(TokenAuthAuthenticator.NEGOTIATE.length()).trim();
        Token accessToken;
        try {
          accessToken = TokenFactory.get().createAccessToken(
              validationSecrets, TokenUtils.decodeToken(authorization));
        } catch (IOException e) {
          httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return null;
        }
        
        String userName = accessToken.getPrincipal().getName(); 
        httpResponse.setStatus(HttpServletResponse.SC_OK);
        return new AuthenticationToken(userName, userName, getType());
      }
    }
  }
  
  String getHttpServerUrl(boolean isSecure, String httpServer) {
    return isSecure ? "https://" : "http://" + httpServer;
  }
}
