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

package org.apache.hadoop.security.tokenauth.has.authorization.rpc;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.ipc.Server;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.authorize.PolicyProvider;
import org.apache.hadoop.security.tokenauth.api.AuthorizationServiceProtocol;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.has.authorization.AuthorizationService;
import org.apache.hadoop.security.tokenauth.has.protocolPB.AuthorizationServiceProtocolPB;
import org.apache.hadoop.security.tokenauth.has.protocolPB.AuthorizationServiceProtocolServerSideTranslatorPB;
import org.apache.hadoop.security.tokenauth.proto.AuthorizationServiceProtocolProtos;

import com.google.protobuf.BlockingService;

public class AuthorizationRPCServer implements AuthorizationServiceProtocol {

  private final AuthorizationService authzService;
  private Configuration config;
  private RPC.Server server;

  public AuthorizationRPCServer(Configuration conf, AuthorizationService authzService,
      PolicyProvider policy) throws IOException {
    this.config = new Configuration(conf);
    this.authzService = authzService;
    /* Authorization RPC server is authentication root, use simple authentication */
    config.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION, "simple");
    RPC.setProtocolEngine(config, AuthorizationServiceProtocolPB.class, ProtobufRpcEngine.class);
    AuthorizationServiceProtocolServerSideTranslatorPB translator = new AuthorizationServiceProtocolServerSideTranslatorPB(
        this);

    BlockingService service = AuthorizationServiceProtocolProtos.AuthorizationService
        .newReflectiveBlockingService(translator);

    InetSocketAddress bindAddr = getAddress(config);
    this.server = new RPC.Builder(config)
        .setProtocol(AuthorizationServiceProtocolPB.class)
        .setInstance(service)
        .setBindAddress(bindAddr.getHostName())
        .setPort(bindAddr.getPort())
        .setNumHandlers(config.getInt(
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_LISTENER_THREAD_COUNT_KEY,
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_LISTENER_THREAD_COUNT_DEFAULT))
        .setVerbose(false).build();

    // set service-level authorization security policy
    if (config.getBoolean(CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, false)) {
      server.refreshServiceAcl(config, policy);
    }
  }

  public void start() {
    this.server.start();
  }

  public InetSocketAddress getAddress() {
    return server.getListenerAddress();
  }

  public void join() throws InterruptedException {
    server.join();
  }

  public void stop() {
    server.stop();
  }

  public boolean isAlive() {
    return server != null;
  }

  @Override
  public byte[] getAccessToken(byte[] identityToken, String protocol) throws IOException {
    String remoteAddr = Server.getRemoteAddress();
    return authzService.getAccessToken(identityToken, protocol, remoteAddr);
  }

  private static InetSocketAddress getAddress(Configuration conf) {
    String addr = conf.get(
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_DEFAULT);
    return NetUtils.createSocketAddr(addr,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_PORT_DEFAULT,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY);
  }
}
