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
package org.apache.hadoop.security.tokenauth.minihas;

import java.net.URL;
import java.net.URLEncoder;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.ws.rs.core.MediaType;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.api.rest.RestUtil;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.junit.Test;

public class TestAuthorizationRestServices extends MiniHasTestCase {
  private String userName = getUserName();
  private String identityServerUrl = "http://localhost:" + getIdentityHttpPort();
  private String authzServerUrl = "http://localhost:" + getAuthzHttpPort();
  private static final String PATH_V1 = RESTParams.PATH_V1;
  private static final String HELLO_URL = RESTParams.HELLO_PATH_SPEC;
  private static final String DO_GET_ACCESS_TOKEN_URL = RESTParams.AUTHORIZE_SERVLET_PATH_SPEC;
  
  @Test
  public void testHello() throws Exception {
    URL url = new URL(authzServerUrl + PATH_V1 + HELLO_URL);
    String result = RestUtil.doHttpConnect(url, null, "GET", 
        null, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  @Test
  public void testAuthorize() throws Exception {
    HASClient client = new HASClientImpl(identityServerUrl, authzServerUrl);
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(userName);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());
    System.out.println(response.getIdentityToken().length);
    
    String tokenEncode =
        URLEncoder.encode(TokenUtils.encodeToken(response.getIdentityToken()), "UTF-8");
    String protocolEncode = URLEncoder.encode(userName, "UTF-8");
    String content =
        RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.PROTOCOL + "=" + protocolEncode;
    URL url = new URL(authzServerUrl + PATH_V1 + DO_GET_ACCESS_TOKEN_URL);
    
    String result = RestUtil.doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);
      
  }
}
