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
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.cache.TokenSerializer;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.shell.kerberos.Krb5ShellHandler;
import org.apache.hadoop.security.tokenauth.shell.kerberos.Krb5UseKeytabHandler;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;

public class GenAuthnFile extends TokenCommand {

  protected GenAuthnFile() throws IOException {
  }

  public static void registerCommands(CommandFactory factory) {
    factory.addClass(GenAuthnFile.class, "-genAuthnFile");
  }

  public static final String NAME = "Generate Authentication File";
  public static final String USAGE = "<authentication file path>";
  public static final String DESCRIPTION = "none description.";

  private static final List<Class<? extends Callback>> readOnlyCallbacks;
  static {
    readOnlyCallbacks = new ArrayList<Class<? extends Callback>>();
    readOnlyCallbacks.add(KerberosCallback.class);
  }

  @Override
  public String getCommandName() {
    return getName();
  }

  @Override
  protected void processArguments(LinkedList<String> args) throws IOException,
      LoginException {
    ensureHASClientInit();
    if (args.size() != 1) {
      throw new IllegalArgumentException();
    }
    final String authnPath = args.get(0);
    final Krb5ShellHandler handler = new Krb5UseKeytabHandler(getConf());
    ClientLogin genAuthnFile = new ClientLogin() {
      List<Callback> callbacks = new LinkedList<Callback>();

      @Override
      protected void loginSucceed(IdentityRequest request,
          IdentityResponse response) throws
          IOException {
        saveCallback(callbacks, request.getCallbacks());
        Token identityToken =
            TokenFactory.get().createIdentityToken(response.getIdentityToken());
        String username = identityToken.getPrincipal().getName();
        TokenSerializer.get().saveAuthnFile(callbacks, username, authnPath,
            handler.getSavedOnlyCallback(), readOnlyCallbacks);
      }

      @Override
      protected void notCompleted(IdentityRequest request,
                                  IdentityResponse response) {
        saveCallback(callbacks, request.getCallbacks());
      }

      private void saveCallback(List<Callback> callbacks, Callback[] cbs) {
        if (cbs != null) {
          for (Callback cb : cbs) {
            callbacks.add(cb);
          }
        }
      }
    };

    genAuthnFile.authenticate(hasClient,handler);
  }


}
