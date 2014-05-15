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

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class Attribute implements Serializable {  
  private static final long serialVersionUID = -394779440888849438L;
  public static final String GROUPS = "groups";
  
  private String name;
  private Set<Object> values;
  
  public Attribute(String name) {
    this.name = name;
    values = Collections.synchronizedSet(new HashSet<Object>());
  }
  
  public String getName() {
    return name;
  }
  
  public Set<Object> getValues() {
    return values;
  }
  
  @SuppressWarnings("unchecked")
  public <T> Set<T> getValues(Class<T> c) {
    if(c == null) {
      throw new NullPointerException("Invalid null Class provided.");
    }
    Set<T> set = null;
    Iterator<Object> iterator = values.iterator();
    while(iterator.hasNext()) {
      Object next = iterator.next();
      if(c.isAssignableFrom(next.getClass())) {
        if(set == null) set = new HashSet<T>();
        set.add((T)next);
      }
    }
    
    return set;
  }
}
