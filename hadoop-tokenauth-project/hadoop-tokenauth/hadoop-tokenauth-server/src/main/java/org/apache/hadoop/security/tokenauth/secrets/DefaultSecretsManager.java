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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class DefaultSecretsManager extends SecretsManager {
  public static final Log LOG = LogFactory.getLog(DefaultSecretsManager.class);

  private SecretsSerializer serializer;
  private Map<String, Secrets> secretsMap;

  DefaultSecretsManager() {
    secretsMap = new HashMap<String, Secrets>();
    serializer = SecretsSerializer.get();
    
    initialize();
  }
  
  void initialize() {
    serializer.loadSecretsMap(secretsMap);
  }

  static final int KEY_LENGTH = 64;
  static final String DEFAULT_KEY_ALGORITHM = "HmacSHA1";
  static final String DEFAULT_KEYPAIR_ALGORITHM = "DSA";
  static final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";
  static final int KEY_SIZE = 1024;

  private final KeyGenerator keyGen;
  {
    try {
      keyGen = KeyGenerator.getInstance(DEFAULT_KEY_ALGORITHM);
      keyGen.init(KEY_LENGTH);
    } catch (NoSuchAlgorithmException nsa) {
      throw new IllegalArgumentException("Can't find " + DEFAULT_KEY_ALGORITHM +
          " algorithm.");
    }
  }

  private final KeyPairGenerator keyPairGen;
  {
    try {
      keyPairGen = KeyPairGenerator.getInstance(DEFAULT_KEYPAIR_ALGORITHM);
      SecureRandom random = SecureRandom.getInstance(DEFAULT_RANDOM_ALGORITHM);
      keyPairGen.initialize(KEY_SIZE, random);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException(
          "Can't find " + DEFAULT_KEYPAIR_ALGORITHM + " algorithm.");
    }
  }

  @Override
  public Secrets getSecrets(String name) {
    if (name == null || name.isEmpty()) {
      throw new NullPointerException("name cannot be null.");
    }
    name = name.toLowerCase();
    synchronized (this) {
      Secrets secrets = secretsMap.get(name);
      if (secrets == null) {
        SecretKey secretKey = keyGen.generateKey();
        KeyPair keyPair = keyPairGen.generateKeyPair();
        secrets = new SecretsImpl(secretKey, 
            keyPair.getPublic(), keyPair.getPrivate());
        
        secretsMap.put(name, secrets);
        serializer.serializeSecrets(name, secrets);
      }
      return secrets;
    }
  }
  
  @Override
  public void removeSecrets(String name) {
    if (name == null || name.isEmpty()) {
      throw new NullPointerException("name cannot be null.");
    }
    name = name.toLowerCase();
    synchronized (this) {
      secretsMap.remove(name);
      serializer.deleteSecrets(name);
    }
  }
}
