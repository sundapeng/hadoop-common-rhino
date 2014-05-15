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
package org.apache.hadoop.security.tokenauth.shell;

import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.has.HASClient;

public abstract class ClientLogin {
  public static final Log LOG = LogFactory.getLog(ClientLogin.class);

  protected IdentityRequest request = null;
  protected IdentityResponse response = null;
  boolean firstLogin = true;
  public void authenticate(HASClient hasClient,
                           ShellCallbackHandler handler) throws IOException,
      LoginException {

    request = new IdentityRequest(null, null);
    response = hasClient.authenticate(request);

    while (response.getResultCode() != IdentityResponse.SUCCEED) {
      if (response.getResultCode() == IdentityResponse.FAILED) {
        if(!firstLogin) {
          throw new LoginException(response.getFailure());
        }
        firstLogin = false;
      } else if (response.getResultCode() == IdentityResponse.RETRIED) {
        System.out.println(response.getFailure());
      } else if (response.getResultCode() == IdentityResponse.NOTCOMPLETED) {
        notCompleted(request, response);
      }

      Callback[] requiredCallbacks = response.getRequiredCallbacks();
      if (requiredCallbacks != null) {
        try {
          handler.handle(response.getRequiredCallbacks());
        } catch (Exception e) {
          throw new LoginException(e.getMessage());
        }
      }
      request = new IdentityRequest(response.getSessionId(),
          response.getRequiredCallbacks());
      response = hasClient.authenticate(request);
    }

    if (IdentityResponse.SUCCEED == response.getResultCode()) {
      LOG.info("Login succeed");
      loginSucceed(request, response);
      return;
    }
  }

  protected abstract void loginSucceed(IdentityRequest 
      request, IdentityResponse response) throws IOException;

  protected abstract void notCompleted(IdentityRequest 
      request, IdentityResponse response);

}
