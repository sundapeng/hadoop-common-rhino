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
  private String identityHttpPort = "8786";
  private String authzHttpPort = "8787";
  private String identityRpcPort = "8781";
  private String authzRpcPort = "8782";

  public MiniHasTestCase() {
    hasBuilder = new MiniHas.Builder();
  }

  /**
   * Set up test environment.
   * It will start mini has server. You can override this function,
   * use setXXXport() to set identity/authz's http/rpc port,
   * or set some custom configurations for hasBuilder,
   * then invoke super.setUp() to start the server.
   * @throws Exception
   */
  @Before
  public void setUp() throws Exception {
    has = hasBuilder
        .setIdentityHttpAddr("localhost:" + identityHttpPort)
        .setAuthoHttpAddr("localhost:" + authzHttpPort)
        .setIdentityRpcAddr("localhost:" + identityRpcPort)
        .setAuthoRpcAddr("localhost:" + authzRpcPort)
        .build();
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
    return identityHttpPort;
  }

  public String getAuthzHttpPort() {
    return authzHttpPort;
  }

  public String getIdentityRpcPort() {
    return identityRpcPort;
  }

  public String getAuthzRpcPort() {
    return authzRpcPort;
  }

  public void setAuthzRpcPort(String port) {
    this.authzRpcPort = port;
  }

  public void setIdentityHttpPort(String port) {
    this.identityHttpPort = port;
  }

  public void setAuthzHttpPort(String port) {
    this.authzHttpPort = port;
  }

  public void setIdentityRpcPort(String port) {
    this.identityRpcPort = port;
  }
  
}
