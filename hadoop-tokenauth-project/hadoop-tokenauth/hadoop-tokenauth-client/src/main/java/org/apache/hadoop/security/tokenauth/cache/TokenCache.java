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

package org.apache.hadoop.security.tokenauth.cache;

import java.io.IOException;
import java.util.List;
import javax.security.auth.callback.Callback;

import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;

public class TokenCache {

  /**
   * Read identity token from cache
   * @throws IOException 
   */
  public static Token getIdentityToken() throws IOException {
    byte[] tokenBytes = TokenSerializer.get().readToken();
    if (tokenBytes == null) {
      return null;
    }
    return TokenFactory.get().createIdentityToken(tokenBytes);
  }
  
  public static void refreshIdentityToken(byte[] identityToken) throws IOException {
    TokenSerializer.get().saveToken(identityToken);
  }
  
  public static void cleanIdentityToken() {
    TokenSerializer.get().cleanIdentityTokenFile();
  }
  
  public static Callback[] getCallbacks(HASClient hasClient, 
      String principal, String authnFilePath) throws IOException {
    List<Callback> callbacks = TokenSerializer.get().
        getCallbacks(hasClient, principal, authnFilePath);
    if(callbacks != null) {
      return callbacks.toArray(new Callback[callbacks.size()]);
    }
    return null;
  }
}
