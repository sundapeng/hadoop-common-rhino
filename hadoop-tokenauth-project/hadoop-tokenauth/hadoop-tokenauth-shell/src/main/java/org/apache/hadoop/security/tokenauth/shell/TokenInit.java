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
import java.util.LinkedList;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.cache.TokenSerializer;
import org.apache.hadoop.security.tokenauth.shell.kerberos.Krb5UseCacheFileHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class TokenInit extends TokenCommand {

  public static final Log LOG = LogFactory.getLog(TokenInit.class);

  protected TokenInit() throws IOException {
  }

  public static final String NAME = "Token Init";
  public static final String USAGE = "";
  public static final String DESCRIPTION = "Generate an Identity Token";

  public static void registerCommands(CommandFactory factory) {
    factory.addClass(TokenInit.class, "-init");
  }

  @Override
  public String getCommandName() {
    return getName();
  }

  @Override
  protected void processArguments(LinkedList<String> args) throws IOException,
      LoginException {
    ensureHASClientInit();
    ClientLogin authn = new ClientLogin() {
      @Override
      protected void loginSucceed(IdentityRequest request,
                                  IdentityResponse response) throws
          IOException {
        TokenSerializer.get().saveToken(response.getIdentityToken());
      }

      @Override
      protected void notCompleted(IdentityRequest 
          request, IdentityResponse response) {
      }
    };
    ShellCallbackHandler handler = new Krb5UseCacheFileHandler(getConf());
    authn.authenticate(hasClient,handler);
  }

}
