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

import static org.apache.hadoop.util.PlatformName.IBM_JAVA;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.security.authentication.client.AbstractAuthenticator;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL.Token;
import org.apache.hadoop.security.authentication.client.AuthenticatedURL;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.client.Authenticator;
import org.apache.hadoop.security.authentication.client.ConnectionConfigurator;
import org.apache.hadoop.security.authentication.client.PseudoAuthenticator;
import org.apache.hadoop.security.tokenauth.api.web.WebHelper;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.login.TokenAuthLoginModule;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenAuthAuthenticator extends AbstractAuthenticator {

  private static Logger LOG = LoggerFactory.getLogger(TokenAuthAuthenticator.class);

  /**
   * HTTP header used by the TokenAuth server endpoint during an authentication sequence.
   */
  public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

  /**
   * HTTP header used by the TokenAuth client endpoint during an authentication sequence.
   */
  public static final String AUTHORIZATION = "Authorization";

  /**
   * HTTP header prefix used by the TokenAuth client/server endpoints during an authentication
   * sequence.
   */
  public static final String NEGOTIATE = "Negotiate";

  private static final String AUTH_HTTP_METHOD = "OPTIONS";

  /*
   * Defines the TokenAuth configuration that will be used to obtain the token principal from the
   * token cache.
   */
  private static class TokenAuthConfiguration extends Configuration {

    private static final String OS_LOGIN_MODULE_NAME;
    private static final boolean windows = System.getProperty("os.name").startsWith("Windows");
    private static final boolean is64Bit = System.getProperty("os.arch").contains("64");
    private static final boolean aix = System.getProperty("os.name").equals("AIX");

    /* Return the OS login module class name */
    private static String getOSLoginModuleName() {
      if (IBM_JAVA) {
        if (windows) {
          return is64Bit ? "com.ibm.security.auth.module.Win64LoginModule"
              : "com.ibm.security.auth.module.NTLoginModule";
        } else if (aix) {
          return is64Bit ? "com.ibm.security.auth.module.AIX64LoginModule"
              : "com.ibm.security.auth.module.AIXLoginModule";
        } else {
          return "com.ibm.security.auth.module.LinuxLoginModule";
        }
      } else {
        return windows ? "com.sun.security.auth.module.NTLoginModule"
            : "com.sun.security.auth.module.UnixLoginModule";
      }
    }

    static {
      OS_LOGIN_MODULE_NAME = getOSLoginModuleName();
    }

    private static final AppConfigurationEntry OS_SPECIFIC_LOGIN = new AppConfigurationEntry(
        OS_LOGIN_MODULE_NAME, AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
        new HashMap<String, String>());

    private static final Map<String, String> USER_TOKENAUTH_OPTIONS = new HashMap<String, String>();

    static {
      USER_TOKENAUTH_OPTIONS.put("doNotPrompt", "true");
      USER_TOKENAUTH_OPTIONS.put("useTokenCache", "true");
      USER_TOKENAUTH_OPTIONS.put("renewToken", "true");
    }

    private static final AppConfigurationEntry USER_TOKENAUTH_LOGIN = new AppConfigurationEntry(
        TokenAuthLoginModule.class.getName(),
        AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL, USER_TOKENAUTH_OPTIONS);

    private static final AppConfigurationEntry[] USER_TOKENAUTH_CONF = new AppConfigurationEntry[] {
        OS_SPECIFIC_LOGIN, USER_TOKENAUTH_LOGIN };

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
      return USER_TOKENAUTH_CONF;
    }
  }

  private Token token;
  private URL url;
  private HttpURLConnection conn;
  private ConnectionConfigurator connConfigurator;
  private String authnCookies;
  private HASClient hasClient;

  public TokenAuthAuthenticator(HASClient hasClient) {
    this.hasClient = hasClient;
  }

  @Override
  public void setConnectionConfigurator(ConnectionConfigurator configurator) {
    connConfigurator = configurator;
  }

  @Override
  public void authenticate(URL url, Token token) throws IOException, AuthenticationException {
    this.token = token;
    if (!token.isSet()) {
      this.url = url;

      conn = (HttpURLConnection) url.openConnection();
      if (connConfigurator != null) {
        conn = connConfigurator.configure(conn);
      }
      conn.setRequestMethod(AUTH_HTTP_METHOD);
      conn.connect();

      if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
        LOG.debug("JDK performed authentication on our behalf.");
        // If the JDK already did the TokenAuth back-and-forth for
        // us, just pull out the token.
        AuthenticatedURL.extractToken(conn, token);
        return;
      } else if (isNegotiate()) {
        LOG.debug("Performing our own TokenAuth sequence.");
        doTokenAuthSequence(token);
      } else {
        LOG.debug("Using fallback authenticator sequence.");
        Authenticator auth = getFallBackAuthenticator();
        // Make sure that the fall back authenticator have the same
        // ConnectionConfigurator, since the method might be overridden.
        // Otherwise the fall back authenticator might not have the information
        // to make the connection (e.g., SSL certificates)
        auth.setConnectionConfigurator(connConfigurator);
        auth.authenticate(url, token);
      }
    }
  }

  /*
   * Indicates if the response is starting a TokenAuth negotiation.
   */
  private boolean isNegotiate() throws IOException {
    boolean negotiate = false;
    if (conn.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
      String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
      negotiate = authHeader != null && authHeader.trim().startsWith(NEGOTIATE);
    }
    return negotiate;
  }

  /**
   * If the specified URL does not support tokenauth authentication, a fallback
   * {@link Authenticator} will be used.
   * <p/>
   * This implementation returns a {@link PseudoAuthenticator}.
   * 
   * @return the fallback {@link Authenticator}.
   */
  protected Authenticator getFallBackAuthenticator() {
    Authenticator auth = new PseudoAuthenticator();
    if (connConfigurator != null) {
      auth.setConnectionConfigurator(connConfigurator);
    }
    return auth;
  }

  private void doTokenAuthSequence(AuthenticatedURL.Token token) throws IOException,
      AuthenticationException {

    try {
      AccessControlContext context = AccessController.getContext();
      Subject subject = Subject.getSubject(context);
      if (subject == null) {
        LOG.debug("No subject in context, logging in");
        subject = new Subject();
        LoginContext login = new LoginContext("", subject, new DefaultHASClientCallbackHandler(
            hasClient), new TokenAuthConfiguration());
        login.login();
      }

      org.apache.hadoop.security.tokenauth.token.Token identityToken = subject
          .getPrivateCredentials(org.apache.hadoop.security.tokenauth.token.Token.class).iterator()
          .next();

      /* get hadoop service protcol */
      String protocol = readProtocol();

      // get access token
      byte[] accessToken = hasClient.getAccessToken(identityToken, protocol);
      String accessTokenStr = TokenUtils.encodeToken(accessToken);
      sendAccessToken(accessTokenStr);

      if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
        throw new AuthenticationException("Authenticate failed.");
      }

      AuthenticatedURL.extractToken(conn, token);
      authnCookies = WebHelper.convertAccessTokenToCookieHeader(accessTokenStr);
    } catch (LoginException e) {
      throw new AuthenticationException(e);
    }
  }

  @Override
  public String getAuthenticatorCookies() throws IOException {
    StringBuffer buffer = new StringBuffer();
    String t = token.toString();
    if (t != null) {
      if (!t.startsWith("\"")) {
        t = "\"" + t + "\"";
      }
      buffer.append(AuthenticatedURL.AUTH_COOKIE + "=" + t).append("; ");
    }
    buffer.append(authnCookies);
    return buffer.toString();
  }

  private void sendAccessToken(String accessToken) throws IOException, AuthenticationException {
    conn = (HttpURLConnection) url.openConnection();
    if (connConfigurator != null) {
      conn = connConfigurator.configure(conn);
    }
    conn.setRequestMethod(AUTH_HTTP_METHOD);

    conn.setRequestProperty(AUTHORIZATION, NEGOTIATE + " " + accessToken);
    conn.connect();
  }

  private String readProtocol() throws IOException, AuthenticationException {
    int status = conn.getResponseCode();
    if (status == HttpURLConnection.HTTP_OK || status == HttpURLConnection.HTTP_UNAUTHORIZED) {
      String authHeader = conn.getHeaderField(WWW_AUTHENTICATE);
      if (authHeader == null || !authHeader.trim().startsWith(NEGOTIATE)) {
        throw new AuthenticationException("Invalid TokenAuth sequence, '" + WWW_AUTHENTICATE
            + "' header incorrect: " + authHeader);
      }
      return authHeader.trim().substring((NEGOTIATE + " ").length()).trim();
    }
    throw new AuthenticationException("Invalid TokenAuth sequence, status code: " + status);
  }

}
