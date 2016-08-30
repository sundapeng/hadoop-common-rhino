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

import org.apache.hadoop.security.tokenauth.util.SecurityUtils;
import org.junit.Test;

public class TestSignature {
  
  final static byte[] data = "hello tokenauth".getBytes();
  
  @Test
  public void testSignature() throws Exception {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    keyPairGen.initialize(512, random);
    
    KeyPair keyPair = keyPairGen.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();
    
    byte[] sign = SecurityUtils.generateSignature(privateKey, data, 0, data.length);
    boolean result = SecurityUtils.verifySignature(publicKey, data, 0, data.length, sign);
    
    assertTrue(result);
    
  }

}
