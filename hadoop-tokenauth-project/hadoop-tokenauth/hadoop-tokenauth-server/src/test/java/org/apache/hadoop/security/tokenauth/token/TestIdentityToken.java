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
import static org.junit.Assert.assertNotNull;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.apache.hadoop.security.tokenauth.has.identity.IdentityTokenInfo;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.secrets.SecretsManager;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.apache.hadoop.security.tokenauth.token.impl.ValidationSecrets;
import org.apache.hadoop.util.Time;
import org.junit.Test;

public class TestIdentityToken {

  @Test
  public void testToken() throws Exception {

    Secrets secrets = SecretsManager.get().getSecrets("test");
    long instant = Time.now();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long oneDay = 24 * 60 * 60 * 1000; // in milliseconds

    Token identityToken = new IdentityToken(secrets, "www.apache.org", "test", instant, instant
        - fiveMins, instant + oneDay, false);
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

    identityToken.getAttributes().add(groups);
    identityToken.getAttributes().add(age);
    identityToken.getAttributes().add(phone);
    identityToken.getAttributes().add(mail);

    byte[] tokenBytes = TokenUtils.getBytesOfToken(identityToken);

    String tokenStr = TokenUtils.encodeToken(tokenBytes);
    System.out.println(tokenStr.length());

    // Read raw
    byte[] decodeTokenBytes = TokenUtils.decodeToken(tokenStr);
    Token rawToken = TokenFactory.get().createIdentityToken(decodeTokenBytes);

    byte[] rawTokenBytes = TokenUtils.getBytesOfToken(rawToken);

    Secrets validationSecrets = new ValidationSecrets(secrets.getSecretKey(),
        secrets.getPublicKey());
    Token resultIdentityToken = TokenFactory.get().createIdentityToken(validationSecrets,
        rawTokenBytes);

    System.out.println(resultIdentityToken.getPrincipal().getName());
    
    assertEquals(tokenBytes.length, rawTokenBytes.length);
    assertEquals(new String(tokenBytes, 0, tokenBytes.length),
                 new String(rawTokenBytes, 0, rawTokenBytes.length));
  }
  
  @Test
  public void testWriteAndReadTokenInfo() throws Exception {
    String testFile = "/tmp/testTokens.dat";
    Secrets secrets = SecretsManager.get().getSecrets("test");
    long instant = Time.now();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long oneDay = 24 * 60 * 60 * 1000; // in milliseconds
    String phoneNumber = "12345678";
    Attribute phone = new Attribute("phone");
    phone.getValues().add(phoneNumber);

    Token identityToken = new IdentityToken(secrets, "www.apache.org", "test", instant, instant
        - fiveMins, instant + oneDay, false);
    identityToken.getAttributes().add(phone);

    IdentityTokenInfo tokenInfo = new IdentityTokenInfo((IdentityToken) identityToken);
    FileOutputStream fos = new FileOutputStream(testFile);
    DataOutput out = new DataOutputStream(fos);
    tokenInfo.write(out);

    FileInputStream fis = new FileInputStream(testFile);
    DataInput in = new DataInputStream(fis);
    tokenInfo.readFields(in);

    // test tokenInfo
    assertEquals(instant, tokenInfo.getCreationTime());

    IdentityToken newToken = tokenInfo.getToken();
    Attribute testPhone = null;
    String testPhoneNumber = null;
    for (Attribute attr : newToken.getAttributes()) {
      if (attr.getName().equals("phone")) {
        testPhone = attr;
      }
    }

    // test token
    assertNotNull(testPhone);

    for (Object o : testPhone.getValues()) {
      testPhoneNumber = o.toString();
    }

    // test attribute value
    assertEquals(testPhoneNumber, phoneNumber);
  }

}
