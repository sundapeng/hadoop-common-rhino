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

package org.apache.hadoop.security.tokenauth.has.authorization.http;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.security.tokenauth.api.web.WEBParams;
import org.apache.hadoop.security.tokenauth.api.web.WebHelper;
import org.apache.hadoop.security.tokenauth.has.authorization.AuthorizationService;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

public class AuthorizationServlet extends HttpServlet {
  private static final long serialVersionUID = -2274102303888827413L;

  @Override
  public void doPost(final HttpServletRequest request,
      final HttpServletResponse response) throws ServletException, IOException {
    String identityToken = request.getParameter(WEBParams.IDENTITY_TOKEN_PARAM);
    String protocol = request.getParameter(WEBParams.PROTOCOL_PARAM);
    String relayState = request.getParameter(WEBParams.RELAYSTATE_PARAM);
    
    authorize(request, response, identityToken, protocol, relayState);
  }
  
  private void authorize(final HttpServletRequest request, final HttpServletResponse 
      response, String identityToken, String protocol, String relayState) throws IOException {
    final ServletContext context = getServletContext();
    final AuthorizationService authorizationService = 
        AuthorizationHttpServer.getServiceFromContext(context);
    
    String remoteAddr = request.getRemoteAddr();
    byte[] accessToken = authorizationService.getAccessToken(
        TokenUtils.decodeToken(identityToken), protocol, remoteAddr);
    
    //successfully
    Map<String, String> formInputs = new HashMap<String, String>();
    formInputs.put(WEBParams.ACCESS_TOKEN_PRARM, TokenUtils.encodeToken(accessToken));
    formInputs.put(WEBParams.RELAYSTATE_PARAM, relayState);
    WebHelper.autoSubmitForm(response, "", relayState, formInputs);
  }
}
