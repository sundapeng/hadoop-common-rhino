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
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.apache.hadoop.security.tokenauth.TokenAuthCallbackHandler;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

public class SaslTokenAuthServer implements SaslServer {
  public static final String MECHANISM = "TOKENAUTH";
  
  @SuppressWarnings("serial")
  public static class SecurityProvider extends Provider {
    public SecurityProvider() {
      super("SaslTokenAuthServer", 1.0, "SASL TokenAuth Authentication Server");
      put("SaslServerFactory." + MECHANISM,
          SaslTokenAuthServerFactory.class.getName());
    }
  }

  public static class SaslTokenAuthServerFactory implements SaslServerFactory {
    @Override
    public SaslServer createSaslServer(String mechanism, String protocol,
        String serverName, Map<String,?> props, CallbackHandler cbh)
            throws SaslException {
      return MECHANISM.equals(mechanism) ? 
          new SaslTokenAuthServer(protocol, serverName, props, cbh) : null; 
    }
    @Override
    public String[] getMechanismNames(Map<String,?> props){
      return new String[]{MECHANISM};
    }
  }
  
  private TokenAuthCallbackHandler callbackHandler;
  private boolean completed;
  private String authzid;
  
  SaslTokenAuthServer(String protocol, String serverName, 
      Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    if(cbh == null || !(cbh instanceof TokenAuthCallbackHandler)) {
      throw new IllegalArgumentException("Should set TokenAuthCallbackHandler");
    }
    callbackHandler = (TokenAuthCallbackHandler)cbh;
  }

  @Override
  public String getMechanismName() {
    return MECHANISM;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if(completed) {
      throw new SaslException("SASL authentication already complete");
    }
    
    if(response == null) {
      throw new IllegalArgumentException("Received null response");
    }
    
    /**
     * Here, access token will be received. 
     * We only have 1 step, verify the access token.
     */
    try {
      Secrets validationSecrets = callbackHandler.getValidationSecrets();
      if(validationSecrets == null) {
        throw new SaslException("Can't find a validation secrets");
      }
      
      Token accessToken = TokenFactory.get().
          createAccessToken(validationSecrets, response);
      
      if (TokenUtils.isExpired(accessToken)) {
        throw new SaslException("Access token for user: " + 
            accessToken.getPrincipal().getName() + " is expired.");
      }
      
      authzid = TokenUtils.encodeToken(response);
      completed = true;
    } catch (Exception e) {
      throw new SaslException("TokenAuth auth failed: " + e.getMessage());
    }
    
    return null;
  }
  
  private void throwIfNotComplete() {
    if (!completed) {
      throw new IllegalStateException("TokenAuth authentication not completed");
    }
  }

  @Override
  public boolean isComplete() {
    return completed;
  }

  @Override
  public String getAuthorizationID() {
    throwIfNotComplete();
    return authzid;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len)
      throws SaslException {
    throwIfNotComplete();
    throw new IllegalStateException(
        "PLAIN supports neither integrity nor privacy");      
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    throwIfNotComplete();
    throw new IllegalStateException(
        "PLAIN supports neither integrity nor privacy"); 
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    throwIfNotComplete();      
    return Sasl.QOP.equals(propName) ? "auth" : null;
  }

  @Override
  public void dispose() throws SaslException {
    callbackHandler = null;
    authzid = null;
  }
}
