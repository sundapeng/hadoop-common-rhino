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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PushbackInputStream;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.security.tokenauth.DefaultTokenAuthCallbackHandler;
import org.apache.hadoop.security.tokenauth.cache.TokenCache;
import org.apache.hadoop.security.tokenauth.login.TokenAuthLoginModule;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenTestCase;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.junit.Test;

class CountFilesAction implements PrivilegedAction<Object> {
  public Object run() {
    File f = new File(".");
    File[] files = f.listFiles();
    return new Integer(files.length);
  }
}

class MyCallbackHandler implements CallbackHandler {
  public void handle(Callback[] callbacks) throws IOException,
      UnsupportedCallbackException {

    for (int i = 0; i < callbacks.length; i++) {
      if (callbacks[i] instanceof TextOutputCallback) {
        // display the message according to the specified type
        TextOutputCallback toc = (TextOutputCallback) callbacks[i];
        switch (toc.getMessageType()) {
        case TextOutputCallback.INFORMATION:
          System.out.println(toc.getMessage());
          break;
        case TextOutputCallback.ERROR:
          System.out.println("ERROR: " + toc.getMessage());
          break;
        case TextOutputCallback.WARNING:
          System.out.println("WARNING: " + toc.getMessage());
          break;
        default:
          throw new IOException("Unsupported message type: "
              + toc.getMessageType());
        }

      } else if (callbacks[i] instanceof NameCallback) {
        // prompt the user for a user name
        NameCallback nc = (NameCallback) callbacks[i];

        // ignore the provided defaultName
        System.err.print(nc.getPrompt());
        System.err.flush();
        nc.setName((new BufferedReader(new InputStreamReader(System.in)))
            .readLine());
      } else if (callbacks[i] instanceof PasswordCallback) {
        // prompt the user for sensitive information
        PasswordCallback pc = (PasswordCallback) callbacks[i];
        System.err.print(pc.getPrompt());
        System.err.flush();
        pc.setPassword(readPassword(System.in));

      } else {
        throw new UnsupportedCallbackException(callbacks[i],
            "Unrecognized Callback");
      }
    }
  }

  // Reads user password from given input stream.
  private char[] readPassword(InputStream in) throws IOException {
    char[] lineBuffer;
    char[] buf;

    buf = lineBuffer = new char[128];

    int room = buf.length;
    int offset = 0;
    int c;

    loop: while (true) {
      switch (c = in.read()) {
      case -1:
      case '\n':
        break loop;

      case '\r':
        int c2 = in.read();
        if ((c2 != '\n') && (c2 != -1)) {
          if (!(in instanceof PushbackInputStream)) {
            in = new PushbackInputStream(in);
          }
          ((PushbackInputStream) in).unread(c2);
        } else
          break loop;

      default:
        if (--room < 0) {
          buf = new char[offset + 128];
          room = buf.length - offset - 1;
          System.arraycopy(lineBuffer, 0, buf, 0, offset);
          Arrays.fill(lineBuffer, ' ');
          lineBuffer = buf;
        }
        buf[offset++] = (char) c;
        break;
      }
    }

    if (offset == 0) {
      return null;
    }

    char[] ret = new char[offset];
    System.arraycopy(buf, 0, ret, 0, offset);
    Arrays.fill(buf, ' ');

    return ret;
  }
}

public class TestTokenAuthLoginModule extends MiniHasTestCase {
  private String identityHttpUrl = "localhost:" + getIdentityHttpPort();
  private String authzHttpUrl = "localhost:" + getAuthzHttpPort();
  
  @Test
  public void testTokenAuthCallbackHandler() throws Exception {
    Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_HTTP_ADDRESS_KEY,
        identityHttpUrl);
    conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_HTTP_ADDRESS_KEY,
        authzHttpUrl);
    conf.setBoolean(CommonConfigurationKeysPublic.HADOOP_SECURITY_TOKENAUTH_SERVER_SSL_ENABLED_KEY,
        false);
    
    LoginContext lc = new LoginContext("jaas", new Subject(), 
        new DefaultTokenAuthCallbackHandler(conf), 
        getLoginConfiguration(false, false, true, false));
    
    lc.login();

    Object o = Subject.doAs(lc.getSubject(), new CountFilesAction());
    System.out.println("User " + lc.getSubject() + " found " + o + " files.");
  }
  
  @Test
  public void testLoginUserFromAuthnFile() throws Exception {
    LoginContext lc = new LoginContext("jaas", new Subject(), 
        new MyCallbackHandler(), 
        getLoginConfiguration(true, false, true, false));
    
    lc.login();

    Object o = Subject.doAs(lc.getSubject(), new CountFilesAction());
    System.out.println("User " + lc.getSubject() + " found " + o + " files.");
  }
  
  @Test
  public void testLoginUserFromTokenCache() throws Exception {
    Token identityToken = TokenTestCase.createToken(null, IdentityToken.class.getName());
    byte[] tokenBytes = TokenUtils.getBytesOfToken(identityToken);
    System.out.println(tokenBytes.length);

    // save token to tokenCache
    TokenCache.refreshIdentityToken(tokenBytes);
    
    // login from reading tokenCache file 
    LoginContext lc = new LoginContext("jaas", new Subject(), 
        new MyCallbackHandler(), 
        getLoginConfiguration(true, true, true, false));
    lc.login();
    Object o = Subject.doAs(lc.getSubject(), new CountFilesAction());
    System.out.println("User " + lc.getSubject() + " found " + o + " files.");
    
    // clear tokenCache file
    TokenCache.cleanIdentityToken();
  }

  private javax.security.auth.login.Configuration getLoginConfiguration(
      final boolean doNotPrompt, final boolean useTokenCache, 
      final boolean useAuthnFile, final boolean renewToken) throws IOException {
    return new javax.security.auth.login.Configuration() {
      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        List<AppConfigurationEntry> entries = new ArrayList<AppConfigurationEntry>();
        Map<String, String> options = new HashMap<String, String>();
        options.put("identityServer", "http://" + identityHttpUrl);
        options.put("authorizationServer", "http://" + authzHttpUrl);
        options.put("doNotPrompt", Boolean.toString(doNotPrompt));
        options.put("useTokenCache", Boolean.toString(useTokenCache));
        options.put("useAuthnFile", Boolean.toString(useAuthnFile));
        options.put("authnFile", getHas().getAuthFileName());
        options.put("renewToken", Boolean.toString(renewToken));
        options.put("principal", getHas().getPrincipal());
        AppConfigurationEntry entry = new AppConfigurationEntry(
            TokenAuthLoginModule.class.getName(),
            LoginModuleControlFlag.REQUIRED,
            options);
        
        entries.add(entry);

        AppConfigurationEntry[] appEntries = new AppConfigurationEntry[entries
            .size()];
        return entries.toArray(appEntries);
      }
    };
  }
}
