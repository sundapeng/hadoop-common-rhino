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

package org.apache.hadoop.security.tokenauth.jaas;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;

public class LoginCallbackHandler implements CallbackHandler {
  
  private AuthenticationContext authnContext;
  private Callback[] submittedCallbacks;
  
  public LoginCallbackHandler(AuthenticationContext authnContext) {
    this.authnContext = authnContext;
  }
  
  public void setSubmittedCallbacks(Callback[] callbacks) {
    submittedCallbacks = callbacks;
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException,
      UnsupportedCallbackException {
    if(callbacks != null) {
      for(int i=0; i<callbacks.length; i++) {
        Callback callback = callbacks[i];
        if(callback instanceof AuthnContextCallback) {
          ((AuthnContextCallback)callback).
            setAuthenticationContext(authnContext);
        } else {
          fillinCallback(callback);
        }
      }
    }
  }
  
  private void fillinCallback(Callback callback) {
    if(submittedCallbacks != null) {
      for (int i=0; i<submittedCallbacks.length; i++) {
        Callback cb = submittedCallbacks[i];
        if(cb instanceof NameCallback && 
            callback instanceof NameCallback) {
          ((NameCallback)callback).setName(((NameCallback)cb).getName());
          return;
        } else if (cb instanceof PasswordCallback && 
            callback instanceof PasswordCallback) {
          ((PasswordCallback)callback).setPassword(((PasswordCallback)cb).getPassword());
          return;
        } else if (cb instanceof RealmCallback &&
            callback instanceof RealmCallback) {
          ((RealmCallback)callback).setText(((RealmCallback)cb).getText());
          return;
        } else if (cb instanceof TextInputCallback &&
            callback instanceof TextInputCallback) {
          ((TextInputCallback)callback).setText(((TextInputCallback)cb).getText());
          return;
        } else if (cb instanceof KerberosCallback &&
            callback instanceof KerberosCallback) {
          ((KerberosCallback)callback).setTicket(((KerberosCallback)cb).getTicket());
          return;
        }
      }
    }
  }

}
