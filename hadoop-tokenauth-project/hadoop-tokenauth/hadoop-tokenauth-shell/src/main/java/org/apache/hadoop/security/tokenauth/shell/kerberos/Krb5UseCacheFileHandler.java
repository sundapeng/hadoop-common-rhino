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
package org.apache.hadoop.security.tokenauth.shell.kerberos;

import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;

public class Krb5UseCacheFileHandler extends Krb5ShellHandler{

  public Krb5UseCacheFileHandler(Configuration conf) {
    super(conf);
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException,
      UnsupportedCallbackException {
    KerberosCallback krbCb = null;
    if (callbacks != null) {
      for (Callback cb : callbacks) {
        if (cb instanceof KerberosCallback) {
          krbCb = (KerberosCallback) cb;
        } else {
          handle(cb);
        }
      }
      if (krbCb != null) {
        byte[] serviceTicket = kerberosLogin.getServiceTicket(krbCb.getKrb5ServPrincipal());
        krbCb.setTicket(serviceTicket);
      }
    }
  }
}
