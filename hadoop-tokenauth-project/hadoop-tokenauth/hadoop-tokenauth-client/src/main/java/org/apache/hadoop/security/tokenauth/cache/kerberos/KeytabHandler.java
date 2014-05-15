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
package org.apache.hadoop.security.tokenauth.cache.kerberos;

import java.io.IOException;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class KeytabHandler {
  public static final Log LOG = LogFactory.getLog(KeytabHandler.class);
  
  private HASClient hasClient;
  
  public KeytabHandler(HASClient hasClient) {
    this.hasClient = hasClient;
  }

  public void handle(List<Callback> callbacks) throws IOException,
      UnsupportedCallbackException {
    int keytabIndex = findKeytabCallback(callbacks);
    if (keytabIndex != -1) {
      String serverPrincipal = getServerPrincipal();
      if (serverPrincipal != null) {
        KerberosLogin kerberosLogin = new KerberosLogin();
        KerberosCallback krbCb = new KerberosCallback();
        for (Callback cb : callbacks) {
          if (cb instanceof KeytabCallback) {
            kerberosLogin.setPrincipal(((KeytabCallback) cb).getPrincipal());
            kerberosLogin.setKeytab(((KeytabCallback) cb).getKeytab());
          }
        }
        krbCb.setTicket(kerberosLogin.getServiceTicket(serverPrincipal));
        callbacks.set(keytabIndex,krbCb);
      }
    }
  }

  public static int findKeytabCallback(List<Callback> callbacks){
    if (callbacks!=null) {
      for (int i=0;i<callbacks.size();i++) {
        if (callbacks.get(i) instanceof KeytabCallback) {
          return i;
        }
      }
    }
    return -1;
  }

  public String getServerPrincipal() {
    try {
      Callback[] callbacks =
          hasClient.authenticate(new IdentityRequest(null,null)).getRequiredCallbacks();
      if (callbacks != null){
        for (Callback cb : callbacks) {
          if (cb instanceof KerberosCallback) {
            return ((KerberosCallback) cb).getKrb5ServPrincipal();
          }
        }
      }
    } catch (IOException e) {
      LOG.error(e.getMessage(),e);
    }
    return null;
  }
}
