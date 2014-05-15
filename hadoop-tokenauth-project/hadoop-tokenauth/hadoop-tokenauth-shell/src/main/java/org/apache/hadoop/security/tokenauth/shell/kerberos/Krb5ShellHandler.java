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

import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.cache.kerberos.KerberosLogin;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.shell.ShellCallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public abstract class Krb5ShellHandler extends ShellCallbackHandler implements CallbackHandler {
  public static final Log LOG = LogFactory.getLog(Krb5ShellHandler.class);
  
  protected KerberosLogin kerberosLogin = new KerberosLogin();

  public Krb5ShellHandler(Configuration conf) {
    super(conf);
  }

  @Override
  public Configuration getConf() {
    return super.getConf();
  }

  protected boolean hasKerberosCallBack(Callback[] callbacks) {
    if (callbacks != null) {
      for (Callback cb : callbacks) {
        if (cb instanceof KerberosCallback)
          return true;
      }
    }
    return false;
  }

  public List<Callback> getSavedOnlyCallback(){
    return null;
  }
}
