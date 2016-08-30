/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.apache.hadoop.security.tokenauth.api.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.sasl.RealmCallback;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class WebHelper {
  private static final String NANECALLBACK_PREF = "NAME-";
  private static final String TEXTINPUTCALLBACK_PREF = "TEXTIN-";
  private static final String TEXTOUTPUTCALLBACK_PREF = "TEXTOUT-";
  private static final String REALMCALLBACK_PREF = "REALM-";
  private static final String PASSWORDCALLBACK_PREF = "PASS-";

  public static void autoSubmitForm(final HttpServletResponse response, 
      String title, String actionUrl, Map<String, String> formInputs) throws IOException {
    if (formInputs == null) {
      throw new NullPointerException("Form inputs can not be null");
    }
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Cache-Control", "no-cache,no-store");
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    try {
      StringBuilder page = new StringBuilder();
      page.append("<html>")
          .append("<head>")
          .append("<title>").append(title).append("</title>")
          .append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />")
          .append("</head>")
          .append("<body onLoad=\"document.forms[0].submit()\">")
          .append("<form action=\"").append(actionUrl).append("\" method=\"POST\" accept-charset=\"UTF-8\">");
      
      Iterator<Entry<String, String>> 
          iterator = formInputs.entrySet().iterator();
      while(iterator.hasNext()) {
        Entry<String, String> entry = (Entry<String, String>)iterator.next();
        page.append("<input type=\"HIDDEN\" name=\"")
            .append(entry.getKey())
            .append("\" value=\"")
            .append(entry.getValue())
            .append("\" />");
      }
      page.append("<noscript><center>")
          .append("<input type=\"SUBMIT\" value=\"Submit\" />")
          .append("</center></noscript>")
          .append("</form>")
          .append("</body>")
          .append("</html>");
      out.write(page.toString());
    } finally {
      out.close();
    }
  }

  public static void renderPage(final HttpServletResponse response, String title,
      String actionUrl, Callback[] callbacks, String relayState, String protocol,
      String failure) throws IOException {
    if (callbacks == null) {
      throw new NullPointerException("callbacks can not be null");
    }
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Cache-Control", "no-cache,no-store");
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    try {
      StringBuilder page = new StringBuilder();
      if (failure != null) {
        page.append("Authencated failed: " + failure);
      }
      page.append("<html>")
          .append("<head>")
          .append("<title>").append(title).append("</title>")
          .append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />")
          .append("</head>")
          .append("<body>")
          .append("<div style=\"width:600px; margin:0 auto; margin-top: 300px\">" +
              "<form action=\"").append(actionUrl).append(
          "\" method=\"POST\" accept-charset=\"UTF-8\">");

      page.append("<table>");
      convertCallbacks(page, callbacks);
      page.append("<input type=\"hidden\" name=\"" + WEBParams.RELAYSTATE_PARAM + "\" value=\"" +
          relayState+"\" />");
      page.append("<input type=\"hidden\" name=\"" + WEBParams.PROTOCOL_PARAM + "\" value=\"" +
          protocol+"\" />");
      page.append("<tr><br/>\n" +
          "<td><input name=\"login\" type=\"submit\" value=\"Login\"/></td>\n" +
          "</tr></table>");
      page.append("</form>")
          .append("</div>")
          .append("</body>")
          .append("</html>");
      out.print(page.toString());
    } finally {
      out.close();
    }
  }

  private static void convertCallbacks(StringBuilder page, Callback[] callbacks) {
    for (Callback cb :callbacks) {
      if (cb instanceof NameCallback) {
        NameCallback nameCb = (NameCallback) cb;
        page.append("<tr>\n" +
            "<td><b>"+nameCb.getPrompt()+" : </b></td>\n<td><input type=\"text\" " +
            "name=\""+ NANECALLBACK_PREF
            + nameCb.getPrompt()+"\"/></td>\n" + "</tr>");
      } else if (cb instanceof PasswordCallback) {
        PasswordCallback pwdCb = (PasswordCallback) cb;
        page.append(" <tr>\n<td><b>" + pwdCb.getPrompt() + " : </b></td>\n" +
            "<td><input type=\"password\" name=\"" + PASSWORDCALLBACK_PREF +
            pwdCb.getPrompt() + "\"></td>\n</tr>");
      } else if (cb instanceof RealmCallback) {
        RealmCallback realmCallback = (RealmCallback) cb;
        page.append(" <tr>\n<td><b>" + realmCallback.getPrompt() + " : </b></td>\n" +
            "<td><input type=\"text\" name=\"" + REALMCALLBACK_PREF +
            realmCallback.getPrompt() + "\"></td>\n</tr>");
      } else if (cb instanceof TextInputCallback) {
        TextInputCallback txtInCb = (TextInputCallback) cb;
        page.append("<tr>\n" +
            "<td><b>"+txtInCb.getPrompt()+" : </b></td>\n" +
            "<td><input type=\"text\" name=\"" + TEXTINPUTCALLBACK_PREF +
            txtInCb.getPrompt()+"\"/></td>\n</tr>");
      } else if (cb instanceof TextOutputCallback) {
        TextOutputCallback txtOutCb = (TextOutputCallback) cb;
        page.append("<tr>" + txtOutCb.getMessage() + "</tr>");
      }
    }
  }
  
  /* access token may be too long to put into a cookie, so we may need multiple cookie */
  private static final String ACCESS_TOKEN_COOKIE = "at";
  private static final String ACCESS_TOKEN_SIZE_COOKIE = "at_size";
  private static final int MAX_ACCESS_TOKEN_COOKIE_SIZE = 4090;
  private static final int MAX_ACCESS_TOKEN_COOKIE_NUM = 15;
  
  public static Map<String, String> convertAccessTokenToCookies(String accessToken) throws IOException {
    Map<String, String> cookies = new HashMap<String, String>();
    int atSize = accessToken.length();
    int atCookieNum = atSize % MAX_ACCESS_TOKEN_COOKIE_SIZE == 0 ? 
        atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE : atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE + 1;
    
    if (atCookieNum > MAX_ACCESS_TOKEN_COOKIE_NUM) {
      throw new IOException("Access token is too long to put into cookies.");
    }
    cookies.put(ACCESS_TOKEN_SIZE_COOKIE, String.valueOf(atSize));
    
    for(int i=0; i<atCookieNum; i++) {
      String atName = i == 0 ?  ACCESS_TOKEN_COOKIE : ACCESS_TOKEN_COOKIE + i;
      String atValue = accessToken.substring(i * MAX_ACCESS_TOKEN_COOKIE_SIZE, 
          (i + 1) < atCookieNum ? (i+1) * MAX_ACCESS_TOKEN_COOKIE_SIZE : atSize);
      cookies.put(atName, atValue);
    }
    return cookies;
  }
  
  public static String convertAccessTokenToCookieHeader(String accessToken) throws IOException {
    Map<String, String> cookies = convertAccessTokenToCookies(accessToken);
    Iterator<Entry<String, String>> iterator = cookies.entrySet().iterator();
    StringBuffer cookieHeader = new StringBuffer();
    boolean first = true;
    while(iterator.hasNext()) {
      Entry<String, String> cookie = iterator.next();
      if (first) {
        first = false;
      } else {
        cookieHeader.append("; ");
      }
      cookieHeader.append(cookie.getKey())
                  .append("=").append("\"" + cookie.getValue() + "\"");
    }
    return cookieHeader.toString();
  }
  
  public static void addAccessTokenToCookie(HttpServletResponse httpResponse, 
      String accessToken, String cookieDomain, String cookiePath) throws IOException {
    if (httpResponse == null || accessToken == null) {
      throw new NullPointerException();
    }
    int atSize = accessToken.length();
    int atCookieNum = atSize % MAX_ACCESS_TOKEN_COOKIE_SIZE == 0 ? 
        atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE : atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE + 1;
    
    if (atCookieNum > MAX_ACCESS_TOKEN_COOKIE_NUM) {
      throw new IOException("Access token is too long to put into cookies.");
    }
    Cookie atSizeCookie = new Cookie(ACCESS_TOKEN_SIZE_COOKIE, String.valueOf(atSize));
    if (cookieDomain != null) {
      atSizeCookie.setDomain(cookieDomain);
    }
    if (cookiePath != null) {
      atSizeCookie.setPath(cookiePath);
    }
    httpResponse.addCookie(atSizeCookie);
    
    for(int i=0; i<atCookieNum; i++) {
      String atName = i == 0 ?  ACCESS_TOKEN_COOKIE : ACCESS_TOKEN_COOKIE + i;
      String atValue = accessToken.substring(i * MAX_ACCESS_TOKEN_COOKIE_SIZE, 
          (i + 1) < atCookieNum ? (i+1) * MAX_ACCESS_TOKEN_COOKIE_SIZE : atSize);
      Cookie atCookie = new Cookie(atName, atValue);
      if (cookieDomain != null) {
        atCookie.setDomain(cookieDomain);
      }
      if (cookiePath != null) {
        atCookie.setPath(cookiePath);
      }
      httpResponse.addCookie(atCookie);
    }
  }
  
  public static String getAccessTokenFromCookie(HttpServletRequest httpRequest) throws IOException {
    if (httpRequest == null) {
      throw new NullPointerException();
    }
    String[] atCookies = new String[MAX_ACCESS_TOKEN_COOKIE_NUM];
    int atSize = -1;
    Cookie[] cookies = httpRequest.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        String cookieName = cookie.getName();
        if (cookieName.equals(ACCESS_TOKEN_SIZE_COOKIE)) {
          atSize = Integer.parseInt(cookie.getValue());
        } else if (cookieName.startsWith(ACCESS_TOKEN_COOKIE)) {
          try {
            if(cookieName.length() == 2) {
              atCookies[0] = cookie.getValue();
            } else {
              int index = Integer.parseInt(cookieName.substring(2));
              atCookies[index] = cookie.getValue();
            }
          } catch (Exception e) {
          }
        }
      }
    }
    if (atSize <= 0) {
      return null;
    }
    int cookieNum = atSize % MAX_ACCESS_TOKEN_COOKIE_SIZE == 0 ? 
        atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE : atSize / MAX_ACCESS_TOKEN_COOKIE_SIZE + 1;
    String accessToken = "";
    for (int i=0; i<cookieNum; i++) {
      if (atCookies[i] == null) {
        throw new IOException ("Part of access token is missed.");
      }
      accessToken += atCookies[i];
    }
    if (accessToken.length() != atSize) {
      throw new IOException("Read access token failed.");
    }
    return accessToken;
  }

  public static Callback getCallback(String callbackkey, String value) {
    if (((String) callbackkey).startsWith(NANECALLBACK_PREF)){
      NameCallback ncb = new NameCallback(((String) callbackkey).substring(NANECALLBACK_PREF.length()));
      ncb.setName(value);
      return ncb;
    } else if (((String) callbackkey).startsWith(PASSWORDCALLBACK_PREF)){
      String promt = ((String) callbackkey).substring(NANECALLBACK_PREF.length());
      PasswordCallback pcb = new PasswordCallback(promt,false);
      pcb.setPassword(value.toCharArray());
      return pcb;
    } else if (((String) callbackkey).startsWith(TEXTINPUTCALLBACK_PREF)){
      String promt = ((String) callbackkey).substring(TEXTINPUTCALLBACK_PREF.length());
      TextInputCallback ticb = new TextInputCallback(promt);
      ticb.setText(value);
      return ticb;
    } else if (((String) callbackkey).startsWith(REALMCALLBACK_PREF)){
      String promt = ((String) callbackkey).substring(REALMCALLBACK_PREF.length());
      RealmCallback rcb = new RealmCallback(promt);
      rcb.setText(value);
      return rcb;
    } else if (((String) callbackkey).startsWith(TEXTOUTPUTCALLBACK_PREF)){
      String promt = ((String) callbackkey).substring(TEXTOUTPUTCALLBACK_PREF.length());
      TextOutputCallback rcb = new TextOutputCallback(0,promt);
      return rcb;
    }
    return null;
  }
}
