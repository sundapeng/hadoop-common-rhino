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

import javax.security.auth.callback.Callback;

public class IdentityRequest {
  private String sessionId;
  private Callback[] callbacks;
  /**
   * needSecrets is true when the client is a service, and 
   * identity server will generate secrets for it. Client 
   * will use the secrets to verify token in future requests.
   */
  private boolean needSecrets; 
  
  public IdentityRequest(String sessionId, 
      Callback[] callbacks) {
    this(sessionId, callbacks, false);
  }
  
  public IdentityRequest(String sessionId,
      Callback[] callbacks, boolean needSecrets) {
    this.sessionId = sessionId;
    this.callbacks = callbacks;
    this.needSecrets = needSecrets;
  }
  
  public String getSessionId() {
    return sessionId;
  }
  
  public Callback[] getCallbacks() {
    return callbacks;
  }
  
  public boolean needSecrets() {
    return needSecrets;
  }
}
