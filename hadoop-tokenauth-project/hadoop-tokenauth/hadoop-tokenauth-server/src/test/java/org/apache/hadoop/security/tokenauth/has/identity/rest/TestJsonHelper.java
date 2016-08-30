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
package org.apache.hadoop.security.tokenauth.has.identity.rest;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.rest.JsonHelper;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.secrets.SecretsManager;

import org.json.simple.JSONObject;
import org.junit.Test;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class TestJsonHelper {
  @Test
  public void testPrivateKey() throws Exception {
    PrivateKey pk = KeyPairGenerator.getInstance("DSA").generateKeyPair().getPrivate();
    assertTrue(Arrays.equals(JsonHelper.toPrivateKey(JsonHelper.toJsonString(pk).
        toJSONString()).getEncoded(), pk.getEncoded()));
  }

  @Test
  public void testPrivateKeyWithNULL() throws Exception {
    PrivateKey pk = new PrivateKey() {
      /**
       * 
       */
      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return null;
      }

      @Override
      public String getFormat() {
        return null;
      }

      @Override
      public byte[] getEncoded() {
        return null;
      }
    };
    try {
      JsonHelper.toPrivateKey(JsonHelper.toJsonString(pk).toJSONString());
    } catch (NullPointerException e) {

    } catch (InvalidKeyException e ) {

    }
  }
  
  @Test
  public void testPublicKey() throws Exception {
    PublicKey pk = KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic();
    assertTrue(Arrays.equals(JsonHelper.toPublicKey(JsonHelper.toJsonString(pk).
        toJSONString()).getEncoded(), pk.getEncoded()));
  }


  @Test
  public void testSecretKey() throws Exception {
    SecretKey pk = KeyGenerator.getInstance("AES").generateKey();
    assertTrue(Arrays.equals(JsonHelper.toSecretKey(JsonHelper.toJsonString(pk).
        toJSONString()).getEncoded(), pk.getEncoded()));
  }
  
  @Test
  public void testSecrets() throws Exception {
    Secrets secrets = SecretsManager.get().getSecrets("test");
    
    String jsonString = JsonHelper.toJsonString(secrets);
    Secrets resultSecrets = JsonHelper.toSecrets(jsonString);
    assertTrue(Arrays.equals(resultSecrets.getPublicKey().getEncoded(), 
        secrets.getPublicKey().getEncoded()));
    assertTrue(Arrays.equals(resultSecrets.getPrivateKey().getEncoded(), 
        secrets.getPrivateKey().getEncoded()));
    assertTrue(Arrays.equals(resultSecrets.getSecretKey().getEncoded(), 
        secrets.getSecretKey().getEncoded()));
  }

  @SuppressWarnings("unchecked")
  @Test
  public  void testJSON() throws Exception {
    JSONObject jsonObject = new JSONObject();
    /*char[] testChar = "password".toCharArray();
    jsonObject.put("hi", String.valueOf(testChar));
    System.out.println(jsonObject.toJSONString());*/
    System.out.println(jsonObject.get("hello2"));
    System.out.println(jsonObject.containsKey("hello2"));

    jsonObject.put("hello2", "world2");
    System.out.println(jsonObject.get("hello2"));
    System.out.println(jsonObject.containsKey("hello2"));
  }
  
  @Test
  public void testIdentityRequest() throws IOException {
    IdentityRequest request = new IdentityRequest("123456", null);
    String jsonString = JsonHelper.toJsonString(request);
    IdentityRequest resultRequest = JsonHelper.toIdentityRequest(jsonString);
    
    System.out.println(resultRequest.getSessionId());
    System.out.println(resultRequest.needSecrets());
    
    assertEquals(resultRequest.getSessionId(), request.getSessionId());
  }
  
  @Test
  public void testIdentityResponse() throws Exception {
    IdentityResponse response = new IdentityResponse("1111", 2222, null, null);
    String jsonString = JsonHelper.toJsonString(response);
    IdentityResponse resultResponse = JsonHelper.toIdentityResponse(jsonString);
    
    System.out.println(resultResponse.getSessionId());
    System.out.println(resultResponse.getResultCode());
    
    assertEquals(resultResponse.getSessionId(), response.getSessionId());
    assertEquals(resultResponse.getResultCode(), response.getResultCode());
  }

}
