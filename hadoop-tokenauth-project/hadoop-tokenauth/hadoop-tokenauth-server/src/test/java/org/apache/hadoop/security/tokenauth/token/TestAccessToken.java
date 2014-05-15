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

import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.secrets.SecretsManager;
import org.apache.hadoop.security.tokenauth.token.impl.AccessToken;
import org.apache.hadoop.security.tokenauth.token.impl.ValidationSecrets;
import org.apache.hadoop.util.Time;
import org.junit.Test;

public class TestAccessToken {
  
  @Test
  public void testToken() throws Exception {
    
    Secrets secrets = SecretsManager.get().getSecrets("test");
    long instant = Time.now();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long oneDay = 24 * 60 * 60 * 1000; // in milliseconds

    Token accessToken = new AccessToken(
        secrets, "www.apache.org", "test", instant, 
        instant - fiveMins, instant + oneDay, false);
    Attribute groups = new Attribute("groups");
    groups.getValues().add("root");
    groups.getValues().add("guest");
    groups.getValues().add("nx");
    groups.getValues().add("svn");
    groups.getValues().add("git");
    Attribute age = new Attribute("age");
    groups.getValues().add(30);
    Attribute phone = new Attribute("phone");
    groups.getValues().add("12345678");
    Attribute mail = new Attribute("mail");
    groups.getValues().add("test@apache.org");
    
    accessToken.getAttributes().add(groups);
    accessToken.getAttributes().add(age);
    accessToken.getAttributes().add(phone);
    accessToken.getAttributes().add(mail);
    
    byte[] tokenBytes = TokenUtils.getBytesOfToken(accessToken);
    
    String tokenStr = TokenUtils.encodeToken(tokenBytes);
    System.out.println(tokenStr.length());
    
    //Read raw
    byte[] decodeTokenBytes = TokenUtils.decodeToken(tokenStr);
    Token rawToken = TokenFactory.get().createAccessToken(decodeTokenBytes);
    
    byte[] rawTokenBytes = TokenUtils.getBytesOfToken(rawToken);
    
    Secrets validationSecrets = new ValidationSecrets(
        secrets.getSecretKey(), secrets.getPublicKey());
    Token resultAccessToken = TokenFactory.get().createAccessToken(validationSecrets, rawTokenBytes);
    
    System.out.println(resultAccessToken.getPrincipal().getName());
    
    assertEquals(tokenBytes.length, rawTokenBytes.length);
    assertEquals(new String(tokenBytes, 0, tokenBytes.length),
                 new String(rawTokenBytes, 0, rawTokenBytes.length));
  }
}
