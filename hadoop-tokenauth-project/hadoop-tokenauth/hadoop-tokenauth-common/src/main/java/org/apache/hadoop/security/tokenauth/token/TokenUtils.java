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

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.apache.hadoop.security.tokenauth.DataOutputBuffer;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;

import org.apache.commons.codec.binary.Base64;

public class TokenUtils {
  private static final float TOKEN_RENEW_WINDOW = 0.80f;
  
  /**
   * Get bytes of Token
   */
  public static byte[] getBytesOfToken(Token token) throws IOException {
    DataOutputBuffer buffer = new DataOutputBuffer();
    token.write(buffer);
    return Arrays.copyOf(buffer.getData(), buffer.getLength());
  }
  
  /**
   * Get groups of user from a token.
   * Groups should be stored as "groups" attribute.
   */
  public static String[] getGroups(Token token) {
    if(token == null) {
      throw new NullPointerException("Token can not be null.");
    }
    
    List<Attribute> attributes = token.getAttributes();
    if(attributes != null) {
      for(Attribute attribute : attributes) {
        if(attribute.getName().equalsIgnoreCase(Attribute.GROUPS)) {
          Set<String> groups = attribute.getValues(String.class);
          return groups != null ? groups.toArray(
              new String[groups.size()]) : new String[0];
        }
      }
    }
    return new String[0];
  }
  
  /**
   * Get attribute of user from a token.
   */
  public static Attribute getAttribute(Token token, String attrName) {
    if (token == null) {
      throw new NullPointerException("Token can not be null.");
    }
    List<Attribute> attributes = token.getAttributes();
    if(attributes != null) {
      for(Attribute attribute : attributes) {
        if(attribute.getName().equalsIgnoreCase(attrName)) {
          return attribute;
        }
      }
    }
    
    return null;
  }
  
  public static long getRefreshTime(Token token) {
    long start = token.getCreationTime();
    long end = token.getExpiryTime();
    return start + (long) ((end - start) * TOKEN_RENEW_WINDOW);
  }
  
  public static boolean isExpired(Token token) {
    return System.currentTimeMillis() >= token.getExpiryTime();
  }
  
  public static String encodeToken(byte[] token) {
    return new String(Base64.encodeBase64(token));
  }

  public static byte[] decodeToken(String token) {
    return Base64.decodeBase64(token.getBytes());
  }
  
  public static Token createTokenInstance(String tokenName, long id, 
      Secrets secrets, String issuer, String user, long issueInstant, 
      long notBefore, long notOnOrAfter, boolean encrypted) throws ClassNotFoundException {
    Class<?> clazz = Class.forName(tokenName);
    return (Token) newInstance(clazz, id, secrets, issuer, user, issueInstant,
        notBefore, notOnOrAfter, encrypted);
  }
  
  public static <T> T newInstance(Class<T> theClass, long id, 
      Secrets secrets, String issuer, String user, long issueInstant, 
      long notBefore, long notOnOrAfter, boolean encrypted) {
    T result;
    try {
      Constructor<T> meth = (Constructor<T>) theClass.getDeclaredConstructor(long.class,
          Secrets.class, String.class, String.class, long.class, long.class, 
          long.class, boolean.class);
      meth.setAccessible(true);
      result = meth.newInstance(id, secrets, issuer, user, issueInstant,
          notBefore, notOnOrAfter, encrypted);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    
    return result;
  }
  
}
