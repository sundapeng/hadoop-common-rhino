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
package org.apache.hadoop.security.tokenauth.has;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import javax.ws.rs.core.MediaType;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.JsonHelper;
import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;

import org.apache.commons.io.IOUtils;
import org.json.simple.parser.ParseException;

/**
 * HASClient rest implementation
 */
public class HASClientImpl extends HASClient {

  private String identityServerUrl;
  private String authzServerUrl;

  private static final String PATH_V1 = RESTParams.PATH_V1;
  private static final String AUTHENTICATE_URL = RESTParams.AUTHENTICATE_SERVLET_PATH_SPEC;
  private static final String RENEW_TOKEN_URL = RESTParams.RENEW_TOKEN_PATH_SPEC;
  private static final String CANCEL_TOKEN_URL = RESTParams.CANCEL_TOKEN_PATH_SPEC;
  private static final String DO_GET_ACCESS_TOKEN_URL = RESTParams.AUTHORIZE_SERVLET_PATH_SPEC;

  public HASClientImpl(String identityServerUrl, String authzServerUrl) {
    this.identityServerUrl = identityServerUrl;
    this.authzServerUrl = authzServerUrl;
  }

  @Override
  public IdentityResponse authenticate(IdentityRequest request) throws
      IOException {
    try {
      String content = JsonHelper.toJsonString(request);
      String urlString = identityServerUrl + PATH_V1 + AUTHENTICATE_URL;
      URL url = new URL(urlString);
      
      String result = doHttpConnect(url, content, "POST", 
          MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
      IdentityResponse response =
          JsonHelper.toIdentityResponse(result);
      return response;
    } catch (ParseException e) {
      throw new IOException(e);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    }
  }

  @Override
  protected byte[] doGetAccessToken(byte[] identityToken, String protocol) throws
      IOException {
    String urlString = authzServerUrl + PATH_V1 + DO_GET_ACCESS_TOKEN_URL;
    URL url = new URL(urlString);
    String tokenEncode =
        URLEncoder.encode(TokenUtils.encodeToken(identityToken), "UTF-8");
    String protocolEncode = URLEncoder.encode(protocol, "UTF-8");
    String content =
        RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.PROTOCOL + "=" + protocolEncode;
    
    String result = doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
    return JsonHelper.toAccessTokenBytes(result);
  }

  @Override
  public Token renewToken(Token identityToken) throws IOException {
    String urlString = identityServerUrl + PATH_V1 + RENEW_TOKEN_URL;
    URL url = new URL(urlString);
    String tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(identityToken)),
        "UTF-8");
    String tokenIdEncode =
        URLEncoder.encode(identityToken.getId() + "", "UTF-8");
    String content =
        RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.TOKEN_ID + "=" + tokenIdEncode;

    String result = doHttpConnect(url, content, "POST", 
        MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);

    return new IdentityToken(TokenUtils.decodeToken(result));
  }

  @Override
  public void cancelToken(Token identityToken) throws IOException {
    String urlString = identityServerUrl + PATH_V1 + CANCEL_TOKEN_URL;
    URL url = new URL(urlString);
    String tokenEncode = URLEncoder.encode(
        TokenUtils.encodeToken(TokenUtils.getBytesOfToken(identityToken)),
        "UTF-8");
    String tokenIdEncode =
        URLEncoder.encode(identityToken.getId() + "", "UTF-8");
    String content =
        RESTParams.IDENTITY_TOKEN + "=" + tokenEncode + "&" + RESTParams.TOKEN_ID + "=" + tokenIdEncode;

    doHttpConnect(url, content, "POST", MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON);
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

  private String sendRequest(HttpURLConnection conn, byte[] content) throws
      IOException {
    if (content != null) {
      OutputStream out = conn.getOutputStream();
      out.write(content);
      out.flush();
      out.close();
    }
    InputStream in = conn.getInputStream();

    int httpStatus = conn.getResponseCode();
    if (httpStatus != 200) {
      throw new IOException("Server at " + conn
          .getURL() + " returned non ok status:" + httpStatus + ", message:" + conn
          .getResponseMessage());
    }
    String result = IOUtils.toString(in);
    if (in != null) in.close();
    return result;
  }

}
