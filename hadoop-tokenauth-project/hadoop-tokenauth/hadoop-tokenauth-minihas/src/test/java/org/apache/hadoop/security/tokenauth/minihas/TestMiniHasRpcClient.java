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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.rpc.HASRpcClient;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.apache.hadoop.conf.Configuration;

import org.junit.Test;

public class TestMiniHasRpcClient extends MiniHasTestCase {
  
  @Test
  public void tesIdentityToken() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.identity.server.rpc-address", "http://localhost:8781");
    conf.set("hadoop.security.authorization.server.rpc-address", "http://localhost:8782");
    HASClient client = new HASRpcClient(conf);
    IdentityRequest request = new IdentityRequest(null,null);
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
    byte[] it = response.getIdentityToken();
    System.out.println(response.getSessionId());
    System.out.println(response.getResultCode());
    System.out.print(it.length);
  }

  @Test
  public void testAccessToken() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.identity.server.rpc-address", "http://localhost:8781");
    conf.set("hadoop.security.authorization.server.rpc-address", "http://localhost:8782");
    HASClient client = new HASRpcClient(conf);
    IdentityRequest request = new IdentityRequest(null,null);
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
    //System.out.println(TokenUtils.encodeToken(response.getIdentityToken()));
    byte[] identityTokenBytes = response.getIdentityToken();
    Token identityToken = new IdentityToken(identityTokenBytes);
    byte[] ac = client.getAccessToken(identityToken, USERNAME);
    System.out.println(ac.length);
  }
  
  @Test
  public void tesRenewToken() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.identity.server.rpc-address", "http://localhost:8781");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ADMIN_KEY, "root");
    HASClient client = new HASRpcClient(conf);
    IdentityRequest request = new IdentityRequest(null,null);
    IdentityResponse response = client.authenticate(request);

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(IDENTITYTOKEN_ADMIN_DEFAULT);
      }
    }
    request = new IdentityRequest(response.getSessionId(), response.getRequiredCallbacks());
    response = client.authenticate(request);
    byte[] tokenBytes = response.getIdentityToken();
    
    IdentityToken token = (IdentityToken) TokenFactory.get().createIdentityToken(
        null, tokenBytes);
    System.out.println(token.getUser());
    System.out.println(token.getId());
    System.out.println(token.getExpiryTime());
    
    IdentityToken newToken = (IdentityToken)client.renewToken(token);
    System.out.println(newToken.getUser());
    System.out.println(newToken.getId());
    System.out.println(newToken.getExpiryTime());
  }
  
  @Test
  public void tesCancelToken() throws Exception {
    Configuration conf = new Configuration();
    conf.set("hadoop.security.identity.server.rpc-address", "http://localhost:8781");
    conf.set("hadoop.security.authorization.server.rpc-address", "http://localhost:8782");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ADMIN_KEY, "root");
    HASClient client = new HASRpcClient(conf);
    IdentityRequest request = new IdentityRequest(null,null);
    IdentityResponse response = client.authenticate(request);

    for (Callback cb : response.getRequiredCallbacks()) {
      if (cb instanceof NameCallback) {
        ((NameCallback) cb).setName(IDENTITYTOKEN_ADMIN_DEFAULT);
      }
    }
    request = new IdentityRequest(response.getSessionId(), response.getRequiredCallbacks());
    response = client.authenticate(request);
    byte[] tokenBytes = response.getIdentityToken();
    
    IdentityToken token = (IdentityToken) TokenFactory.get().createIdentityToken(
        null, tokenBytes);
    System.out.println(token.getUser());
    System.out.println(token.getId());
    System.out.println(token.getExpiryTime());
    
    client.cancelToken(token);
  }

}
