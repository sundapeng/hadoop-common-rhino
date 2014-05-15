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

package org.apache.hadoop.security.tokenauth.token.impl;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.secrets.Secrets;

/**
 * Validation secrets are used to validate token.
 * Secret key is used to decrypt token.
 * Public key is used to verify signature of token.
 */
public class ValidationSecrets implements Secrets {
  private SecretKey secretKey;
  private PublicKey publicKey;
  
  public ValidationSecrets (SecretKey secretKey, PublicKey publicKey) {
    this.secretKey = secretKey;
    this.publicKey = publicKey;
  }

  @Override
  public SecretKey getSecretKey() {
    return secretKey;
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public PrivateKey getPrivateKey() {
    return null;
  }

}
