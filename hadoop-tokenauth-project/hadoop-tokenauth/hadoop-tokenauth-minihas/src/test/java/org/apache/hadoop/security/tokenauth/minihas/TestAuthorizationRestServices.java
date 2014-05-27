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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.ws.rs.core.MediaType;

import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.junit.Test;

public class TestAuthorizationRestServices extends MiniHasTestCase {
  private String userName = getUserName();
  private String identityHttpPort = getIdentityHttpPort();
  private String authoHttpPort = getAuthoHttpPort();
  
  @Test
  public void testHello() throws Exception {
    HttpURLConnection conn = null;
    InputStream in = null;
    try {
      URL url = new URL("http://localhost:" + authoHttpPort + "/ws/v1/hello");
      conn = (HttpURLConnection)url.openConnection();
      conn.setDoOutput(true);
      conn.setRequestMethod("GET");
      conn.setRequestProperty("Accept", MediaType.APPLICATION_JSON);
      conn.setRequestProperty("charset", "utf-8");
      
      System.out.println(conn.getResponseCode());
      System.out.println(conn.getResponseMessage());
      System.out.println(conn.getHeaderField("Content-Length"));
      
      in = conn.getInputStream();
      
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      byte[] b = new byte[1024];
      int nRead = 0;
      while((nRead = in.read(b)) != -1) {
        buffer.write(b, 0, nRead);
      }
      
      System.out.println(buffer.toString("utf-8"));
    } finally {
      IOUtils.closeStream(in);
      if (conn != null) {
        conn.disconnect();
      }
    }
  }
  
  @Test
  public void testAuthorize() throws Exception {
    HASClient client = new HASClientImpl("http://localhost:" + identityHttpPort,
        "http://localhost:" + authoHttpPort);
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
    
    HttpURLConnection conn = null;
    OutputStream out = null;
    InputStream in = null;
    try {
      String tokenEncode =
          URLEncoder.encode(TokenUtils.encodeToken(response.getIdentityToken()), "UTF-8");
      String protocolEncode = URLEncoder.encode(userName, "UTF-8");
      String contentString =
          RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.PROTOCOL + "=" + protocolEncode;
      byte[] content = contentString.getBytes("UTF-8");
      URL url = new URL("http://localhost:" + authoHttpPort + "/ws/v1/authorize");
      conn = (HttpURLConnection)url.openConnection();
      conn.setDoOutput(true);
      conn.setRequestMethod("POST");
      conn.setRequestProperty("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);
      conn.setRequestProperty("Accept", MediaType.APPLICATION_JSON);
      conn.setRequestProperty("charset", "utf-8");
      conn.setRequestProperty("Content-Length", "" + String.valueOf(content.length));
      
      out = conn.getOutputStream();
      out.write(content);
      out.flush();
      out.close();
      
      System.out.println(conn.getResponseCode());
      System.out.println(conn.getResponseMessage());
      
      in = conn.getInputStream();
      
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      byte[] b = new byte[1024];
      int nRead = 0;
      while((nRead = in.read(b)) != -1) {
        buffer.write(b, 0, nRead);
      }
      
      System.out.println(buffer.toString("utf-8"));
      
    } finally {
      IOUtils.closeStream(in);
      if (conn != null) {
        conn.disconnect();
      }
    }
  }
  
}
