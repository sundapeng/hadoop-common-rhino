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

package org.apache.hadoop.security.tokenauth.login;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.hadoop.security.tokenauth.HASClientCallbackHandler;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.cache.TokenCache;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.HASClientImpl;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenPrincipal;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.ValidationSecrets;

public class TokenAuthLoginModule implements LoginModule {
  
  private Subject subject;
  private CallbackHandler callbackHandler;
  
  private boolean doNotPrompt = false;
  private boolean useTokenCache = false;
  private boolean useAuthnFile = false;
  private String authnFileName = null;
  private String principalName = null;
  
  private boolean renewToken = false;
  
  private String identityServer = null;
  private String authorizationServer = null;

  private Token identityToken = null;
  private HASClient hasClient = null;
  private Secrets secrets = null;
  
  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    
    this.callbackHandler = callbackHandler;
    if (callbackHandler != null && callbackHandler instanceof HASClientCallbackHandler) {
      hasClient = ((HASClientCallbackHandler)callbackHandler).getHASClient();
    }
    
    doNotPrompt = "true".equalsIgnoreCase((String)options.get("doNotPrompt"));
    useTokenCache = "true".equalsIgnoreCase((String)options.get("useTokenCache"));
    useAuthnFile = "true".equalsIgnoreCase((String)options.get("useAuthnFile"));
    authnFileName = (String)options.get("authnFile");
    principalName = (String)options.get("principal");
    renewToken = "true".equalsIgnoreCase((String)options.get("renewToken"));
    
    if (hasClient == null) {
      identityServer = (String)options.get("identityServer");
      authorizationServer = (String)options.get("authorizationServer");
      if (identityServer == null || authorizationServer == null) {
        throw new IllegalArgumentException("identityServer and authorizationServer can't be null.");
      }
      hasClient = new HASClientImpl(identityServer, authorizationServer);
    }
  }

  @Override
  public boolean login() throws LoginException {
    validateConfiguration();
    
    Principal principal = null;
    if (principalName != null) {
      principal = new TokenPrincipal(principalName);
    } else {
      if (subject.getPrincipals(TokenPrincipal.class).iterator().hasNext()) {
        principal = subject.getPrincipals(TokenPrincipal.class).iterator().next();
      }   
    }
    
    try {
      if (useTokenCache) {
        identityToken = TokenCache.getIdentityToken();
        
        if (identityToken != null) {
          if (renewToken) {
            identityToken = renewIdentityToken(identityToken);
          } else {
            if (TokenUtils.isExpired(identityToken)) {
              identityToken = null;
            }
          }
        }
      }
      
      if (identityToken == null) {
        if (useAuthnFile) {
          if (principal == null) {
            throw new LoginException("No principal for authentication from authnFile: " + authnFileName);
          }
          Callback[] callbacks = TokenCache.getCallbacks(hasClient, principal.getName(), authnFileName);
          
          IdentityRequest request = new IdentityRequest(null, callbacks, true);
          IdentityResponse response = hasClient.authenticate(request);
          if(response.getResultCode() != IdentityResponse.SUCCEED) {
            throw new LoginException(response.getFailure());
          }
         
          identityToken = TokenFactory.get().createIdentityToken(
              response.getIdentityToken());
          secrets = new ValidationSecrets(
              response.getSecretKey(), response.getPublicKey());
        }
      }
      
      if (identityToken == null) {
        if (!doNotPrompt) {
          if (callbackHandler == null) {
            throw new LoginException("No CallbackHandler "
                + "available "
                + "to garner authentication "
                + "information from the user");
          }
          IdentityRequest request = new IdentityRequest(null, null);
          IdentityResponse response = hasClient.authenticate(request);
          while (response.getResultCode() != IdentityResponse.SUCCEED) {
            if (response.getResultCode() == IdentityResponse.FAILED) {
              throw new LoginException(response.getFailure());
            }
            
            Callback[] callbacks = response.getRequiredCallbacks();
            try {
              callbackHandler.handle(callbacks);
            } catch (UnsupportedCallbackException e) {
              throw new LoginException(e.getMessage() +" not available to garner "
               + " authentication information " + " from the user");
            }
            request = new IdentityRequest(response.getSessionId(), callbacks);
            response = hasClient.authenticate(request);
          }
          
          identityToken = TokenFactory.get().createIdentityToken(
              response.getIdentityToken());
          secrets = new ValidationSecrets(
              response.getSecretKey(), response.getPublicKey());
        }
      }
      
      if (identityToken == null) {
        throw new LoginException("Identity token can not be obtained from the Identity server.");
      }
    } catch (IOException e) {
      throw new LoginException (e.getMessage());
    }
    
    return true;
  }
  
  private Token renewIdentityToken(Token identityToken) {
    Token token = identityToken;
    try {
      if(TokenUtils.isExpired(token)) {
        token = hasClient.renewToken(token);
      }
    } catch (Exception e) {
      token = null;
    }
    
    return token;
  }

  @Override
  public boolean commit() throws LoginException {
    if (identityToken != null) {
      subject.getPrincipals().add(identityToken.getPrincipal());
      subject.getPrivateCredentials().add(identityToken);
      if (secrets != null) {
        subject.getPrivateCredentials().add(secrets);
      }
      
      return true;
    }
    return false;
  }

  @Override
  public boolean abort() throws LoginException {
    logout();
    return true;
  }

  @Override
  public boolean logout() throws LoginException {
    subject.getPrincipals().remove(identityToken.getPrincipal());
    subject.getPrivateCredentials().remove(identityToken);
    if (secrets != null) {
      subject.getPrivateCredentials().remove(secrets);
    }
    identityToken = null;
    secrets = null;
    return true;
  }
  
  private void validateConfiguration() throws LoginException {
    if (doNotPrompt && !useTokenCache && !useAuthnFile)
        throw new LoginException
            ("Configuration Error"
             + " - either doNotPrompt should be "
             + " false or at least one of useTokenCache, "
             + " useAuthnFile should be true");
    /*if (tokenCacheName != null && !useTokenCache)
        throw new LoginException
            ("Configuration Error "
             + " - useTokenCache should be set "
             + "to true to use the token cache"
             + tokenCacheName);*/
    if (authnFileName != null && !useAuthnFile)
        throw new LoginException
            ("Configuration Error - useAuthnFile should be set to true "
             + "to use the authn file" + authnFileName);
    if (authnFileName == null && useAuthnFile)
        throw new LoginException
            ("Configuration Error - authn file should be set "
                + " when useAuthnFile is true");
    if (renewToken && !useTokenCache)
        throw new LoginException
            ("Configuration Error"
             + " - either useTokenCache should be "
             + " true or renewToken should be false");
  }
}
