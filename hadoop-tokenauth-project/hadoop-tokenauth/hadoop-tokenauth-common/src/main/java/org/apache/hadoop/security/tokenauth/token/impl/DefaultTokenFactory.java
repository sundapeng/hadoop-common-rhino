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

package org.apache.hadoop.security.tokenauth.token.impl;

import java.io.IOException;

import org.apache.hadoop.security.tokenauth.DataInputBuffer;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.impl.AbstractToken.InvalidToken;

public class DefaultTokenFactory extends TokenFactory {
  
  public DefaultTokenFactory() {
  }
  
  @Override
  public Token createToken(byte[] tokenBytes) throws IOException {
    Token token;
    try {
      token = createIdentityToken(tokenBytes);
    } catch (InvalidToken e) {
      token = createAccessToken(tokenBytes);
    }
    
    return token;
  }
  
  @Override
  public Token createIdentityToken(byte[] identityToken) throws IOException {
    IdentityToken token = new IdentityToken(identityToken);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(identityToken, 0, identityToken.length);
    token.readFields(buffer);
    return token;
  }
  
  @Override
  public Token createIdentityToken(Secrets secrets, byte[] identityToken) throws IOException {
    IdentityToken token = new IdentityToken(identityToken, secrets);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(identityToken, 0, identityToken.length);
    token.readFields(buffer);
    return token;
  }
  
  @Override
  public Token createAccessToken(byte[] accessToken) throws IOException {
    AccessToken token = new AccessToken(accessToken);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(accessToken, 0, accessToken.length);
    token.readFields(buffer);
    return token;
  }
  
  @Override
  public Token createAccessToken(Secrets secrets, byte[] accessToken) throws IOException {
    AccessToken token = new AccessToken(accessToken, secrets);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(accessToken, 0, accessToken.length);
    token.readFields(buffer);
    
    return token;
  }
}
