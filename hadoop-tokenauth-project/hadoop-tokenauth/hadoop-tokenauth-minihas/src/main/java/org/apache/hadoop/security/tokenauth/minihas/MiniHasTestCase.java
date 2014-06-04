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

import org.junit.After;
import org.junit.Before;

/**
 * MiniHasTestCase provides a base class for using MiniHas with other
 * testcases. MiniHasTestCase starts the MiniHas (@Before) before
 * running tests, and stop the MiniHas (@After) after the testcases.
 * <p>
 * Users can directly inherit this class and implement their own test
 * functions using the default ports, or override functions setUp() and
 * tearDown() to set other configurations to hasBuilder and invoke
 * super's setUp() to start mini has server.
 *
 */

public class MiniHasTestCase {
  protected MiniHas.Builder hasBuilder;
  private MiniHas has;
  private static final String USERNAME = System.getProperty("user.name");
  private static final String IDENTITYTOKEN_ADMIN_DEFAULT = USERNAME;
  private static String identityHttpDefaultPort = "8786";
  private static String AuthoHttpDefaultPort = "8787";
  private static String identityRpcDefaultPort = "8781";
  private static String AuthoRpcDefaultPort = "8782";

  public MiniHasTestCase() {
    // Set default values to hasBuilder
    hasBuilder = new MiniHas.Builder()
        .setIdentityHttpAddr("localhost:" + identityHttpDefaultPort)
        .setAuthoHttpAddr("localhost:" + AuthoHttpDefaultPort)
        .setIdentityRpcAddr("localhost:" + identityRpcDefaultPort)
        .setAuthoRpcAddr("localhost:" + AuthoRpcDefaultPort);
  }

  /**
   * Set up test environment.
   * It will start mini has server. You can override this function to
   * set some custom configurations for hasBuilder and invoke
   * super.setUp() to start the server.
   * @throws Exception
   */
  @Before
  public void setUp() throws Exception {
    has = hasBuilder.build();
    has.waitHasUp();
  }

  @After
  public void tearDown() throws Exception {
    if (has != null) {
      has.shutdown();
    }
  }

  public MiniHas getHas() {
    return has;
  }

  public String getUserName() {
    return USERNAME;
  }

  public String getAdminName() {
    return IDENTITYTOKEN_ADMIN_DEFAULT;
  }

  public String getIdentityHttpPort() {
    return identityHttpDefaultPort;
  }

  public static String getAuthoHttpPort() {
    return AuthoHttpDefaultPort;
  }

  public static String getIdentityRpcPort() {
    return identityRpcDefaultPort;
  }

  public static String getAuthoRpcPort() {
    return AuthoRpcDefaultPort;
  }

}
