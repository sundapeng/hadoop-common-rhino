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

package org.apache.hadoop.security.tokenauth.secrets;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.token.impl.ValidationSecrets;
import org.apache.hadoop.security.tokenauth.util.SecurityUtils;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestValidationSecrets {
  
  final static byte[] data = "hello tokenauth".getBytes();
  static SecretKey secretKey;
  static PublicKey publicKey;
  static PrivateKey privateKey;
  
  @BeforeClass
  public static void prepareKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128);
    secretKey = keyGen.generateKey();
    
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    keyPairGen.initialize(512, random);
    KeyPair keyPair = keyPairGen.generateKeyPair();
    publicKey = keyPair.getPublic();
    privateKey = keyPair.getPrivate();
  }
  
  @Test
  public void testVerifyKey() throws Exception {
    
    Secrets secrets = new ValidationSecrets(secretKey, publicKey);
    assertEquals(secrets.getSecretKey().getEncoded().length, secretKey.getEncoded().length);
    assertEquals(secrets.getPublicKey().getEncoded().length, publicKey.getEncoded().length);
  }
  
  @Test
  public void testSigature() throws Exception {
    
    Secrets secrets = new ValidationSecrets(secretKey, publicKey);
    byte[] sign = SecurityUtils.generateSignature(privateKey, data, 0, data.length);
    boolean result = SecurityUtils.verifySignature(secrets.getPublicKey(), data, 0, data.length, sign);
    
    assertTrue(result);
  }

}
