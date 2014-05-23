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
package org.apache.hadoop.security.tokenauth.minihas;

import org.junit.AfterClass;
import org.junit.BeforeClass;

public class MiniHasTestCase {
  protected static MiniHas has;
  protected static final String USERNAME = System.getProperty("user.name");
  protected static final String IDENTITYTOKEN_ADMIN_DEFAULT = USERNAME;
  
  @BeforeClass
  public static void setUp() throws Exception {
    has = new MiniHas.Builder()
              .setIdentityHttpAddr("localhost:8786")
              .setAuthoHttpAddr("localhost:8787")
              .build();
    has.waitHasUp();
  }
  
  @AfterClass
  public static void tearDown() throws Exception {
    if(has != null) {
      has.shutdown();
    }
  }
}
