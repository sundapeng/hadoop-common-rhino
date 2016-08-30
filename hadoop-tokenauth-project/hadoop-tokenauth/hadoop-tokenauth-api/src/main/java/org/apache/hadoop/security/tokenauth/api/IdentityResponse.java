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

package org.apache.hadoop.security.tokenauth.api;

import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;

public class IdentityResponse {
  private String sessionId;
  private int resultCode;
  private String failureCause;
  private Callback[] requiredCallbacks;
  private byte[] identityToken;
  /**
   * Secret key and Public key are obtained after authentication.
   * secret key is used to descrpt identity/access token,
   * public key is used to verify identity/access token.
   */
  private SecretKey secretKey;
  private PublicKey publicKey;
  
  //login result
  public static final int SUCCEED = 0;
  public static final int FAILED = 1;
  public static final int NOTCOMPLETED = 2;
  public static final int RETRIED = 3;
  
  public IdentityResponse(String sessionId, int resultCode, 
      String failureCause, Callback[] requiredCallbacks) {
    this.sessionId = sessionId;
    this.resultCode = resultCode;
    this.failureCause = failureCause;
    this.requiredCallbacks = requiredCallbacks;
  }
  
  public IdentityResponse(String sessionId, int resultCode, 
      String failureCause, Callback[] requiredCallbacks, 
      byte[] identityToken, SecretKey secretKey, PublicKey publicKey) {
    this(sessionId, resultCode, failureCause, requiredCallbacks);
    this.identityToken = identityToken;
    this.secretKey = secretKey;
    this.publicKey = publicKey;
  }
  
  public String getSessionId() {
    return sessionId;
  }
  
  public int getResultCode() {
    return resultCode;
  }
  
  public String getFailure() {
    return failureCause;
  }
  
  public Callback[] getRequiredCallbacks() {
    return requiredCallbacks;
  }
  
  public byte[] getIdentityToken() {
    return identityToken;
  }
  
  /**
   * Secret key is used to decrypt identity/access token
   */
  public SecretKey getSecretKey() {
    return secretKey;
  }
  
  /**
   * Public key is used to verify identity/access token
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }
}
