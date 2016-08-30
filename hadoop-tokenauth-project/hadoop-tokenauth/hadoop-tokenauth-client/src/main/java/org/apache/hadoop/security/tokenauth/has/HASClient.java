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
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

public abstract class HASClient {
  
  private Map<String, byte[]> accessTokens;

  public abstract IdentityResponse authenticate(IdentityRequest request) throws IOException;

  public byte[] getAccessToken(Token identityToken, String protocol) throws IOException {
    byte[] accessToken = null;
    synchronized(HASClient.class) {
      if(accessTokens != null) {
        accessToken = accessTokens.get(protocol);
      } else {
        accessTokens = new HashMap<String, byte[]>();
      }
      boolean renew = accessToken == null;
      if(accessToken != null) {
        Token token = TokenFactory.get().createAccessToken(accessToken);
        if (System.currentTimeMillis() >= TokenUtils.getRefreshTime(token)) {
          renew = true;
        }
      }
      
      if(renew) {
        accessToken = doGetAccessToken(TokenUtils.getBytesOfToken(identityToken), protocol);
        accessTokens.put(protocol, accessToken);
      }
    }
    return accessToken;
  }
  
  protected abstract byte[] doGetAccessToken(byte[] identityToken, String protocol) throws IOException;

  public abstract Token renewToken(Token identityToken) throws IOException;

  public abstract void cancelToken(Token identityToken) throws IOException;

}
