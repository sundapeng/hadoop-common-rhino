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

package org.apache.hadoop.security.tokenauth.cache;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenTestCase;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.junit.Test;

public class TestTokenSerializer extends TokenTestCase {

  @Test
  public void testReadToken() throws Exception {
    Token identityToken = createToken(null, IdentityToken.class.getName());
    byte[] tokenBytes = TokenUtils.getBytesOfToken(identityToken);
    System.out.println(tokenBytes.length);

    TokenSerializer.get().saveToken(tokenBytes);
    
    Token readToken = TokenFactory.get().createIdentityToken(TokenSerializer.get().readToken());
    System.out.println(readToken.getPrincipal().getName());
    assertEquals(readToken.getPrincipal().getName(), DEFAULT_PRINCIAL_NAME);
    
    TokenSerializer.get().cleanIdentityTokenFile();
    
  }
  
  @Test
  public void testSaveAuthnFile() throws Exception {
    String username = "test";
    String authnPath = "test.authfile";
    
    List<Callback> callbacks = new LinkedList<Callback>();
    Callback cb = new NameCallback("prompt");
    ((NameCallback)cb).setName(username);
    callbacks.add(cb);

    final List<Class<? extends Callback>> readOnlyCallbacks;
    readOnlyCallbacks = new ArrayList<Class<? extends Callback>>();
    readOnlyCallbacks.add(KerberosCallback.class);

    TokenSerializer.get().saveAuthnFile(callbacks, username, authnPath,
        null, readOnlyCallbacks);
    cleanAuthnFile(authnPath);
  }
  
  private void cleanAuthnFile(String authnPath) {
    File file = new File(authnPath);
    if (file != null && file.exists()) {
      file.delete();
    }
    System.out.println("AuthnFile is deleted.");
  }
  
}
