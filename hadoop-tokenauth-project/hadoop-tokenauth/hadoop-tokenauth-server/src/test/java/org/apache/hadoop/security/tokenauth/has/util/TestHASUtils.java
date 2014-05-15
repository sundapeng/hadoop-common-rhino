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

package org.apache.hadoop.security.tokenauth.has.util;

import static org.junit.Assert.assertEquals;

import java.net.InetSocketAddress;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.junit.Test;

public class TestHASUtils {
  private final String host = "192.168.10.11";
  private final int port = 1234;
  
  @Test
  public void testGetISServiceRpcAddresses() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY, host + ":" + port);
    InetSocketAddress addr = HASUtils.getISServiceRpcAddresses(conf);
    assertEquals(addr.getHostName(), host);
    assertEquals(addr.getPort(), port);
  }
  
  @Test
  public void testGetAuthzServiceRpcAddresses() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY, host + ":" + port);
    InetSocketAddress addr = HASUtils.getAuthzServiceRpcAddresses(conf);
    assertEquals(addr.getHostName(), host);
    assertEquals(addr.getPort(), port);
  }
  
  @Test
  public void testGetUserNameFromKerberos() throws Exception {
    String FQDN = "server-15388.novalocal@NOVALOCAL";
    String username = HASUtils.getUserNameFromKerberos(FQDN);
    System.out.println(username);
    assertEquals(username, "server-15388.novalocal");
  }
}
