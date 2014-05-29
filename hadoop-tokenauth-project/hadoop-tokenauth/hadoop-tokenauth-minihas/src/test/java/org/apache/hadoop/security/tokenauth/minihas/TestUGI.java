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
package org.apache.hadoop.security.tokenauth.minihas;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.cache.TokenCache;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenTestCase;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.junit.Test;

public class TestUGI extends MiniHasTestCase {
  
  @Test
  public void testLoginUserFromAuthnFile() throws Exception {
    UserGroupInformation.loginUserFromAuthnFile(getHas().getPrincipal(), getHas().getAuthFileName());
  }
  
  @Test
  public void testLoginUserFromTokenCache() throws Exception {
    Token identityToken = TokenTestCase.createToken(null, IdentityToken.class.getName());
    byte[] tokenBytes = TokenUtils.getBytesOfToken(identityToken);
    System.out.println(tokenBytes.length);

    // save token to tokenCache
    TokenCache.refreshIdentityToken(tokenBytes);
    
    // read token from tokenCache
    UserGroupInformation.getUGIFromTokenCache(getHas().getPrincipal(), getHas().getAuthFileName());
    
    // clear tokenCache file
    TokenCache.cleanIdentityToken();
  }
  
}
