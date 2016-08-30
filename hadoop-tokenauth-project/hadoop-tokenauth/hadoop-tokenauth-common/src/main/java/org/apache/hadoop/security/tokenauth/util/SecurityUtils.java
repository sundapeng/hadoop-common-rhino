/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.apache.hadoop.security.tokenauth.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class SecurityUtils {  
  private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withDSA";
  
  private static Signature sig;

  public static byte[] generateSignature(
      PrivateKey privateKey, byte[] data, int off, int len) 
      throws InvalidKeyException, SignatureException {
    synchronized(SecurityUtils.class) {
      if(sig == null) {
        try {
          sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
          throw new IllegalArgumentException(
              "Can't find " + DEFAULT_SIGNATURE_ALGORITHM + " algorithm.");
        }
      }
    }
    sig.initSign(privateKey);
    sig.update(data, off, len);
    return sig.sign();
  }
  
  public static boolean verifySignature(
      PublicKey publicKey, byte[] data, int off, int len, byte[] signature) 
      throws InvalidKeyException, SignatureException {
    synchronized(SecurityUtils.class) {
      if(sig == null) {
        try {
          sig = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
          throw new IllegalArgumentException(
              "Can't find " + DEFAULT_SIGNATURE_ALGORITHM + " algorithm.");
        }
      }
    }
    sig.initVerify(publicKey);
    sig.update(data, off, len);
    return sig.verify(signature);
  }
  
}
