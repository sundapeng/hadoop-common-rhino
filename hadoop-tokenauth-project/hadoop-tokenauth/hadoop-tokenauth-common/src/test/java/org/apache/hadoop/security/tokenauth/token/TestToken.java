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

package org.apache.hadoop.security.tokenauth.token;

import static org.junit.Assert.assertEquals;

import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.junit.Test;

public class TestToken extends TokenTestCase {

  @Test
  public void testToken() throws Exception {
    Token identityToken = createToken(null, IdentityToken.class.getName());
    byte[] tokenBytes = TokenUtils.getBytesOfToken(identityToken);
    System.out.println(tokenBytes.length);

    Token resultToken = TokenFactory.get().createIdentityToken(tokenBytes);

    System.out.println("ID: " + resultToken.getId());
    System.out.println("Principal :" + resultToken.getPrincipal().getName());
    System.out.print("Attribute : {");
    for (Attribute attr : resultToken.getAttributes()) {
      System.out.print(attr.getName() + " ");
    }
    System.out.println("}");
    System.out.println("CreationTime: " + resultToken.getCreationTime());
    System.out.println("ExpiryTime: " + resultToken.getExpiryTime());
    assertEquals(resultToken.getPrincipal().getName(), DEFAULT_PRINCIAL_NAME);
  }
  
}
