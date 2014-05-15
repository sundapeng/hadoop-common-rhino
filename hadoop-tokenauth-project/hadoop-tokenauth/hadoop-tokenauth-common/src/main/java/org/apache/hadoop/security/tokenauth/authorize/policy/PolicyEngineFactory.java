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

package org.apache.hadoop.security.tokenauth.authorize.policy;

import java.lang.reflect.Constructor;

public class PolicyEngineFactory {
  
  private static ClassLoader classLoader;
  static {
    classLoader = Thread.currentThread().getContextClassLoader();
    if (classLoader == null) {
      classLoader = PolicyEngineFactory.class.getClassLoader();
    }
  }
  
  public static PolicyEngine createPolicyEngine(String 
      engineName, String policy) throws ClassNotFoundException {
    Class<?> clazz = Class.forName(engineName);
    return (PolicyEngine) newInstance(clazz, policy);
  }
  
  public static PolicyEngine createPolicyEngine(String policy) {
    return (PolicyEngine) newInstance(RhinoPolicyEngine.class, policy);
  }
  
  static <T> T newInstance(Class<T> theClass, String policy) {
    T result;
    try {
      Constructor<T> meth = (Constructor<T>) theClass.getDeclaredConstructor(String.class);
      meth.setAccessible(true);
      result = meth.newInstance(policy);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    
    return result;
  }
  
}
