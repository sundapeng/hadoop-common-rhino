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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.ws.rs.core.MediaType;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.JsonHelper;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.api.rest.RestUtil;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.AccessToken;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.json.simple.parser.ParseException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class TestIdentityRestServices extends MiniHasTestCase {
  private String userName = getUserName();
  private String adminName = getAdminName();
  private static int RENEW_PERIOD = 60 * 60 * 24;  // unit: second
  
  private String identityServerUrl = "http://localhost:" + getIdentityHttpPort();
  private String authzServerUrl = "http://localhost:" + getAuthzHttpPort();
  private static final String PATH_V1 = RESTParams.PATH_V1;
  private static final String HELLO_URL = RESTParams.HELLO_PATH_SPEC;
  private static final String AUTHENTICATE_URL = RESTParams.AUTHENTICATE_SERVLET_PATH_SPEC;
  private static final String GET_SECRETS_URL = RESTParams.GET_SECRETS_PATH_SPEC;
  private static final String RENEW_TOKEN_URL = RESTParams.RENEW_TOKEN_PATH_SPEC;
  private static final String CANCEL_TOKEN_URL = RESTParams.CANCEL_TOKEN_PATH_SPEC;
  private static final String DO_GET_ACCESS_TOKEN_URL = RESTParams.AUTHORIZE_SERVLET_PATH_SPEC;

  @Before
  public void setUp() throws Exception {
    // The max lifetime for identity token is 2 days, so it can be renewed only once.
    hasBuilder.setOtherProperty(
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_MAX_LIFETIME_KEY,
        String.valueOf(60 * 60 * 24 * 2));
    super.setUp();
  }
  
  @Test
  public void testHello() throws Exception {
    URL url = new URL(identityServerUrl + PATH_V1 + HELLO_URL);
    String result = RestUtil.doHttpConnect(url, null, "GET", 
        null, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  @Test
  public void testAuthenticate() throws Exception {
    try {
      IdentityRequest request = new IdentityRequest("12345678", null);
      String content = JsonHelper.toJsonString(request);
      URL url = new URL(identityServerUrl + PATH_V1 + AUTHENTICATE_URL);
      String result = RestUtil.doHttpConnect(url, content, "POST", 
          MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
      System.out.println(result);
      IdentityResponse response =
          JsonHelper.toIdentityResponse(result);
      System.out.println(response.getSessionId());
    } catch (ParseException e) {
      throw new IOException(e);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    }
  }
  
  @Test
  public void testGetSecrets() throws Exception {
    HASClient client = new HASClientImpl(identityServerUrl, null);
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
    String content = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&"
        + RESTParams.PROTOCOL + "=" + protocolEncode;
    URL url = new URL(identityServerUrl + PATH_V1 + GET_SECRETS_URL);
    String result = RestUtil.doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  @Test
  public void testRenewToken() throws Exception {
    // Authenticate to get an identity token.
    HASClient client = new HASClientImpl(identityServerUrl, null);
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(adminName);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    IdentityToken token = TokenFactory.get().createIdentityToken(
        null, response.getIdentityToken());
    System.out.println(token.getUser());
    System.out.println(token.getId());
    System.out.println(token.getExpiryTime());
    
    // 1st renewal, expected to be success.
    URL url = new URL(identityServerUrl + PATH_V1 + RENEW_TOKEN_URL);
    String content = getRenewTokenContent(token);
    String result = RestUtil.doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);
    
    IdentityToken newToken = TokenFactory.get().createIdentityToken(
        JsonHelper.toIdentityTokenBytes(result));
    assertEquals(token.getId(), newToken.getId());
    assertEquals(token.getUser(), newToken.getUser());
    assertEquals(token.getCreationTime(), newToken.getCreationTime());
    assertEquals(token.getExpiryTime() + 1000 * RENEW_PERIOD,
        newToken.getExpiryTime());

    // 2nd renewal, expected to received a response with status code 403.
    content = getRenewTokenContent(newToken);
    RestUtil.doHttpConnect(url, content, "POST", MediaType.APPLICATION_FORM_URLENCODED,
        MediaType.APPLICATION_JSON, HttpURLConnection.HTTP_FORBIDDEN);
  }

  @Test
  public void testCancelToken() throws Exception {
    // Get an identity token
    HASClient client = new HASClientImpl(identityServerUrl, null);
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(adminName);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    IdentityToken token = TokenFactory.get().createIdentityToken(
        null, response.getIdentityToken());
    
    // Validate identity token
    URL authzUrl = new URL(authzServerUrl + PATH_V1 + DO_GET_ACCESS_TOKEN_URL);
    String tokenEncode = URLEncoder.encode(TokenUtils.encodeToken(response.getIdentityToken()), "UTF-8");
    String protocolEncode = URLEncoder.encode(userName, "UTF-8");
    String authzContent = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.PROTOCOL + "="
        + protocolEncode;
    String authzResult = RestUtil.doHttpConnect(authzUrl, authzContent, "POST", MediaType.APPLICATION_FORM_URLENCODED,
        MediaType.APPLICATION_JSON);
    AccessToken accessToken = (AccessToken) TokenFactory.get().createAccessToken(
        JsonHelper.toAccessTokenBytes(authzResult));
    assertEquals(userName, accessToken.getUser());

    // Revoke the identity token
    URL cancelTokenUrl = new URL(identityServerUrl + PATH_V1 + CANCEL_TOKEN_URL);
    tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(token)),
        "UTF-8");
    String tokenIdEncode =
        URLEncoder.encode(token.getId() + "", "UTF-8");
    String cancelTokenContent = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + 
        RESTParams.TOKEN_ID + "=" + tokenIdEncode;
    String result = RestUtil.doHttpConnect(cancelTokenUrl, cancelTokenContent, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);

    // Try to get an access token with revoked identity token
    RestUtil.doHttpConnect(authzUrl, authzContent, "POST", MediaType.APPLICATION_FORM_URLENCODED,
        MediaType.APPLICATION_JSON, HttpURLConnection.HTTP_FORBIDDEN);
  }

  private String getRenewTokenContent(IdentityToken token)
      throws UnsupportedEncodingException, IOException {
    String tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(token)), "UTF-8");
    String tokenIdEncode = URLEncoder.encode(token.getId() + "", "UTF-8");
    return RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&"
        + RESTParams.TOKEN_ID + "=" + tokenIdEncode;
  }

}
