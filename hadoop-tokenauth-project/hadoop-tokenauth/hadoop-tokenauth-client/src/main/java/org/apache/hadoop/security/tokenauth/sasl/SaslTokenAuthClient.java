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

package org.apache.hadoop.security.tokenauth.sasl;

import java.security.Provider;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.apache.hadoop.security.tokenauth.TokenAuthCallbackHandler;

public class SaslTokenAuthClient implements SaslClient {
  public static final String MECHANISM = "TOKENAUTH";
  
  @SuppressWarnings("serial")
  public static class SecurityProvider extends Provider {
    public SecurityProvider() {
      super("SaslTokenAuthClient", 1.0, "SASL TokenAuth Authentication Client");
      put("SaslClientFactory." + MECHANISM,
          SaslTokenAuthClientFactory.class.getName());
    }
  }

  public static class SaslTokenAuthClientFactory implements SaslClientFactory {
    
    @Override
    public String[] getMechanismNames(Map<String,?> props){
      return new String[]{MECHANISM};
    }

    @Override
    public SaslClient createSaslClient(String[] mechanisms,
        String authorizationId, String protocol, String serverName,
        Map<String, ?> props, CallbackHandler cbh) throws SaslException {
      
      for(int i=0; i<mechanisms.length; i++) {
        if(mechanisms[i].equals(MECHANISM)) {
          return new SaslTokenAuthClient(authorizationId, protocol, serverName, 
              props, cbh);
        }
      }

      return null;
    }
  }
  
  private boolean completed;
  private byte[] accessToken;
  
  /**
   * authzID is the user, we ignore it here
   * protocol indicates the Hadoop service
   * serverName is the target host
   */
  SaslTokenAuthClient(String authzID, String protocol, String serverName, 
      Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    
    if(cbh == null || !(cbh instanceof TokenAuthCallbackHandler)) {
      throw new IllegalArgumentException("Should set TokenAuthCallbackHandler");
    }
    TokenAuthCallbackHandler callbackHandler = (TokenAuthCallbackHandler)cbh;
    
    try {
      accessToken = callbackHandler.getAccessToken(protocol);
    } catch (Exception e) {
      throw new SaslException("Can't get the access token");
    }
  }

  @Override
  public String getMechanismName() {
    return MECHANISM;
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }
  
  private void throwIfNotComplete() {
    if(!completed) {
      throw new IllegalStateException("TokenAuth authentication not completed.");
    }
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    /*
     * step 1, we will send access token to Hadoop service.
     */
    
    this.completed = true;
    return accessToken;
  }

  @Override
  public boolean isComplete() {
    return completed;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len)
      throws SaslException {
    throwIfNotComplete();
    throw new IllegalStateException(
        "TokenAuth supports neither integrity nor privacy"); 
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    throwIfNotComplete();
    throw new IllegalStateException(
        "TokenAuth supports neither integrity nor privacy");     
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    throwIfNotComplete();
    return Sasl.QOP.equals(propName) ? "auth" : null;
  }

  @Override
  public void dispose() throws SaslException {
    
  }

}
