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

package org.apache.hadoop.security.tokenauth.has.identity.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.web.WEBParams;
import org.apache.hadoop.security.tokenauth.api.web.WebHelper;
import org.apache.hadoop.security.tokenauth.has.authorization.http.AuthorizationHttpServer;
import org.apache.hadoop.security.tokenauth.has.identity.IdentityService;
import org.apache.hadoop.security.tokenauth.jaas.session.LoginSession;
import org.apache.hadoop.security.tokenauth.jaas.session.SessionManager;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.util.Time;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class AuthenticationServlet extends HttpServlet {
  private static final long serialVersionUID = -3208686717003940106L;
  private static final Log LOG = LogFactory.getLog(AuthenticationServlet.class);
  
  private static final String SESSIONID_COOKIE = "t_session_id";
  private static final String SESSION_TOKEN = "IdentityToken";

  @Override
  public void doGet(final HttpServletRequest request,
      final HttpServletResponse response) throws ServletException, IOException {
    doPost(request, response);
  }

  @Override
  public void doPost(final HttpServletRequest request,
      final HttpServletResponse response) throws ServletException, IOException {
    String relayState = request.getParameter(WEBParams.RELAYSTATE_PARAM);
    String protocol = request.getParameter(WEBParams.PROTOCOL_PARAM);
    
    String sessionId = getSessionId(request);
    if (sessionId != null) {
      LoginSession session = SessionManager.get().getSession(sessionId);
      if (session != null) {
        if (session.isValid() && !session.expired()) {
          Token identityToken = (Token)session.getValue(SESSION_TOKEN);
          if (identityToken != null) {
            if (Time.now() > TokenUtils.getRefreshTime(identityToken)) {
              final ServletContext context = getServletContext();
              final Configuration conf = IdentityHttpServer.getConfFromContext(context);
              finishAuthentication(response, TokenUtils.
                  getBytesOfToken(identityToken), relayState, protocol, conf);
              return;
            } else {
              LOG.info("Identity token expires.");
              session.invalidate();
              sessionId = null;
            }
          }
        } else {
          sessionId = null;
        }
      }
    }
    
    Callback[] callbacks = getCallbacks(request);
    authenticate(request, response, sessionId, callbacks, relayState, protocol);
  }
  
  private String getSessionId(final HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(SESSIONID_COOKIE)) {
          return cookie.getValue();
        }
      }
    }
    
    return null;
  }

  private void authenticate(final HttpServletRequest request,
      final HttpServletResponse response, String sessionId, Callback[] callbacks,
      String relayState, String protocol) throws IOException {
    final ServletContext context = getServletContext();
    final IdentityService identityService = IdentityHttpServer.getServiceFromContext(context);
    final Configuration conf = IdentityHttpServer.getConfFromContext(context);
    
    IdentityRequest identityRequest = new IdentityRequest(sessionId, callbacks);
    IdentityResponse identityResponse = identityService.authenticate(identityRequest, request, response);
    Cookie cookie = new Cookie(SESSIONID_COOKIE, identityResponse.getSessionId());
    response.addCookie(cookie);
    
    if (identityResponse.getResultCode() == IdentityResponse.FAILED) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, identityResponse.getFailure());
      
    } else if (identityResponse.getResultCode() != IdentityResponse.SUCCEED) {
      if (containsKerberos(identityResponse)){
        kerberosAuthenticate(request, response, identityResponse, conf);
      } else {
        WebHelper.renderPage(response, "Hadoop Login Page", WEBParams.AUTHENTICATE_SERVLET_PATH_SPEC,
            identityResponse.getRequiredCallbacks(), relayState, protocol, identityResponse.getFailure());
      }
    } else {
      //login successfully
      byte[] identityToken = identityResponse.getIdentityToken();
      LoginSession session = SessionManager.get().getSession(identityResponse.getSessionId());
      session.putValue(SESSION_TOKEN, TokenFactory.get().createIdentityToken(identityToken));
      finishAuthentication(response, identityToken, relayState, protocol, conf);
    }
  }
  
  private void finishAuthentication(final HttpServletResponse response, 
      byte[] identityToken, String relayState, String protocol, Configuration conf) throws IOException {
    
    //relayState, protocol
    Map<String, String> formInputs = new HashMap<String, String>();
    formInputs.put(WEBParams.IDENTITY_TOKEN_PARAM, TokenUtils.encodeToken(identityToken));
    formInputs.put(WEBParams.RELAYSTATE_PARAM, relayState);
    formInputs.put(WEBParams.PROTOCOL_PARAM, protocol);
    WebHelper.autoSubmitForm(response, "", AuthorizationHttpServer.getAccessTokenUrl(conf), formInputs);
  }
  
  @SuppressWarnings("rawtypes")
  private Callback[] getCallbacks(HttpServletRequest request) throws IOException {

    List<Callback> callbackList = new ArrayList<Callback>();
    Map params = request.getParameterMap();
    for (Object key: params.keySet()) {
      String value = request.getParameter((String) key);
      Callback callback = WebHelper.getCallback((String)key,value);
      if (callback != null) {
        callbackList.add(callback);
      }
    }
    
    Callback[] callbacks = null;
    int num = callbackList.size();
    if (num > 0){
      callbacks = callbackList.toArray(new Callback[num]); 
    }
    
    if (hasKerberosHeader(request)) {
      callbacks = addKerberosCallback(callbacks,request);
    }
    
    return callbacks;
  }

  private Callback[] addKerberosCallback(Callback[] callbacks,
      HttpServletRequest request) {
    String authorization = request.getHeader(KerberosAuthenticator.AUTHORIZATION);
    authorization = authorization.substring(KerberosAuthenticator.NEGOTIATE.length()).trim();
    final Base64 base64 = new Base64(0);
    final byte[] clientToken = base64.decode(authorization);

    KerberosCallback kerberosCallback = new KerberosCallback();
    kerberosCallback.setTicket(clientToken);
    if (callbacks != null) {
      Callback[] addKerberos = Arrays.copyOf(callbacks, callbacks.length + 1);
      addKerberos[callbacks.length] = kerberosCallback;
      return addKerberos;
    } else {
      return new Callback[]{kerberosCallback};
    }
  }

  private boolean hasKerberosHeader(HttpServletRequest request) {
    String authorization = request.getHeader(KerberosAuthenticator.AUTHORIZATION);
    return ! (authorization == null
        || !authorization.startsWith(KerberosAuthenticator.NEGOTIATE));
  }

  private boolean containsKerberos(IdentityResponse identityResponse) {
    if (identityResponse != null
        && identityResponse.getRequiredCallbacks()!=null ) {
      Callback[] callbacks = identityResponse.getRequiredCallbacks();
      if (callbacks != null) {
        for (Callback cb: callbacks) {
          if (cb instanceof KerberosCallback)
            return true;
        }
      }
    }
    return false;
  }
  
  private void kerberosAuthenticate(final HttpServletRequest request,
      final HttpServletResponse response, IdentityResponse identityResponse, 
      final Configuration conf) throws IOException {
    if(! hasKerberosHeader(request)) {
      response.setHeader(KerberosAuthenticator.WWW_AUTHENTICATE, KerberosAuthenticator.NEGOTIATE);
    }
    
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, identityResponse.getFailure());
  }
}
