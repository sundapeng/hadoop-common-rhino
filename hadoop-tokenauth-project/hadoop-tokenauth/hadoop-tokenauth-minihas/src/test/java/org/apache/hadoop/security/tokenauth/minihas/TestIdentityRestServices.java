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
import java.io.InputStream;
import java.io.OutputStream;
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
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.json.simple.parser.ParseException;
import org.junit.Test;

import org.apache.commons.io.IOUtils;

public class TestIdentityRestServices extends MiniHasTestCase {
  
  @Test
  public void testHello() throws Exception {
    URL url = new URL("http://localhost:8786/ws/v1/hello");
    String result = doHttpConnect(url, null, "GET", 
        null, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  @Test
  public void testAuthenticate() throws Exception {
    try {
      IdentityRequest request = new IdentityRequest("12345678", null);
      String content = JsonHelper.toJsonString(request);
      URL url = new URL("http://localhost:8786/ws/v1/authenticate");
      String result = doHttpConnect(url, content, "POST", 
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
    HASClient client = new HASClientImpl("http://localhost:8786", "http://localhost:8787");
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    
    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(USERNAME);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());
    System.out.println(response.getIdentityToken().length);
    
    String tokenEncode =
        URLEncoder.encode(TokenUtils.encodeToken(response.getIdentityToken()), "UTF-8");
    String protocolEncode = URLEncoder.encode(USERNAME, "UTF-8");
    String content = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" 
        + RESTParams.PROTOCOL + "=" + protocolEncode;
    URL url = new URL("http://localhost:8786/ws/v1/getSecrets");
    String result = doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  @Test
  public void testRenewToken() throws Exception {
    HASClient client = new HASClientImpl("http://localhost:8786", "http://localhost:8787");
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(IDENTITYTOKEN_ADMIN_DEFAULT);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    IdentityToken token = (IdentityToken) TokenFactory.get().createIdentityToken(
        null, response.getIdentityToken());
    System.out.println(token.getUser());
    System.out.println(token.getId());
    System.out.println(token.getExpiryTime());
    
    URL url = new URL("http://localhost:8786/ws/v1/renewToken");
    String tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(token)),
        "UTF-8");
    String tokenIdEncode =
        URLEncoder.encode(token.getId() + "", "UTF-8");
    String content = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + 
        RESTParams.TOKEN_ID + "=" + tokenIdEncode;

    String result = doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);

    IdentityToken newToken = new IdentityToken(TokenUtils.decodeToken(result));
    System.out.println(newToken.getUser());
    System.out.println(newToken.getId());
    System.out.println(newToken.getExpiryTime());
  }
  
  @Test
  public void testCancelToken() throws Exception {
    HASClient client = new HASClientImpl("http://localhost:8786", "http://localhost:8787");
    IdentityRequest request = new IdentityRequest(null, null);
    IdentityResponse response = client.authenticate(request);
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(IDENTITYTOKEN_ADMIN_DEFAULT);
      }
    }
    request = new IdentityRequest(response.getSessionId(),response.getRequiredCallbacks());
    response = client.authenticate(request);
    IdentityToken token = (IdentityToken) TokenFactory.get().createIdentityToken(
        null, response.getIdentityToken());
    System.out.println(token.getUser());
    System.out.println(token.getId());
    System.out.println(token.getExpiryTime());
    
    URL url = new URL("http://localhost:8786/ws/v1/cancelToken");
    String tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(token)),
        "UTF-8");
    String tokenIdEncode =
        URLEncoder.encode(token.getId() + "", "UTF-8");
    String content = RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + 
        RESTParams.TOKEN_ID + "=" + tokenIdEncode;

    String result = doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    System.out.println(result);
  }
  
  private String doHttpConnect(URL url, String content, String requestMethod,
      String contentType, String acceptType) throws IOException {
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setDoOutput(true);
    conn.setRequestMethod(requestMethod);
    conn.setRequestProperty("Accept", acceptType);
    conn.setRequestProperty("charset", "utf-8");
    if (content != null) {
      conn.setRequestProperty("Content-Type", contentType);
      conn.setRequestProperty("Content-Length",
          "" + String.valueOf(content.getBytes().length));
    }

    return content != null ? sendRequest(conn, content.getBytes()) :
      sendRequest(conn, null);
  }
  
  private String sendRequest(HttpURLConnection conn, byte[] content)
      throws IOException {
    if (content != null) {
      OutputStream out = conn.getOutputStream();
      out.write(content);
      out.flush();
      out.close();
    }
    InputStream in = conn.getInputStream();

    int httpStatus = conn.getResponseCode();
    if (httpStatus != 200) {
      throw new IOException("Server at " + conn.getURL()
          + " returned non ok status:" + httpStatus + ", message:"
          + conn.getResponseMessage());
    }
    String result = IOUtils.toString(in);
    if (in != null)
      in.close();
    return result;
  }
}
