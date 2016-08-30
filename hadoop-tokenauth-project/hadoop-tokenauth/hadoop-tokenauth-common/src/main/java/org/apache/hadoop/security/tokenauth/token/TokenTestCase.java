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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Attribute;
import org.apache.hadoop.security.tokenauth.token.Token;

enum ATTRIBUTE_TYPE {
  GROUP("groups"), AGE("age"), PHONE("phone"), MAIL("mail");
  private ATTRIBUTE_TYPE(String name) {
    setName(name);
  }
  
  private String name;
  
  public String getName() {
    return name;
  }
  
  public void setName(String name) {
    this.name = name;
  }
}

public class TokenTestCase {
  protected static final String DEFAULT_PRINCIAL_NAME = "test";
  
  public static Token createToken(Secrets secrets, String tokenName) throws Exception {
    if (secrets == null) {
      secrets = getSecrets();
    }
    
    long instant = System.currentTimeMillis();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long oneDay = 24 * 60 * 60 * 1000; // in milliseconds
    
    Token token = TokenUtils.createTokenInstance(tokenName, 0, secrets, 
        "www.apache.org", DEFAULT_PRINCIAL_NAME, instant,
        instant - fiveMins, instant + oneDay, false);
    Attribute groups = new Attribute(ATTRIBUTE_TYPE.GROUP.getName());
    groups.getValues().add("root");
    groups.getValues().add("guest");
    groups.getValues().add("nx");
    groups.getValues().add("svn");
    groups.getValues().add("git");
    Attribute age = new Attribute(ATTRIBUTE_TYPE.AGE.getName());
    age.getValues().add(30);
    Attribute phone = new Attribute(ATTRIBUTE_TYPE.PHONE.getName());
    phone.getValues().add("12345678");
    Attribute mail = new Attribute(ATTRIBUTE_TYPE.MAIL.getName());
    mail.getValues().add("test@apache.org");

    token.getAttributes().add(groups);
    token.getAttributes().add(age);
    token.getAttributes().add(phone);
    token.getAttributes().add(mail);
    
    return token;
  }
  
  public static Secrets getSecrets() throws NoSuchAlgorithmException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128);
    
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    keyPairGen.initialize(512, random);
    final KeyPair keyPair = keyPairGen.generateKeyPair();
    
    return new Secrets() {
      @Override
      public SecretKey getSecretKey() {
        return keyGen.generateKey();
      }

      @Override
      public PublicKey getPublicKey() {
        return keyPair.getPublic();
      }

      @Override
      public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
      }
    };
  }
  
}
