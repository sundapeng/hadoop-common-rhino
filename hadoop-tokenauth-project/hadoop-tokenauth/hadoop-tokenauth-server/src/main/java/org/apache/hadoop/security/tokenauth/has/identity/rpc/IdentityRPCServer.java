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

package org.apache.hadoop.security.tokenauth.has.identity.rpc;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.authorize.PolicyProvider;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.has.identity.IdentityService;
import org.apache.hadoop.security.tokenauth.has.protocol.IdentityServiceProtocals;
import org.apache.hadoop.security.tokenauth.has.protocolPB.IdentityServiceProtocolPB;
import org.apache.hadoop.security.tokenauth.has.protocolPB.IdentityServiceProtocolServerSideTranslatorPB;
import org.apache.hadoop.security.tokenauth.has.protocolPB.SecretsProtocolPB;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.SecretsProtocolProtos;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;

import com.google.protobuf.BlockingService;

public class IdentityRPCServer implements IdentityServiceProtocals {
  private final IdentityService identityService;
  private RPC.Server server;

  public IdentityRPCServer(Configuration conf, IdentityService identityService,
      PolicyProvider policy) throws IOException {
    this.identityService = identityService;
    /* Identity RPC server is authentication root, use simple authentication */
    conf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION, "simple");

    RPC.setProtocolEngine(conf, IdentityServiceProtocolPB.class, ProtobufRpcEngine.class);
    IdentityServiceProtocolServerSideTranslatorPB translator = new IdentityServiceProtocolServerSideTranslatorPB(
        this);

    BlockingService identityProtocolService = IdentityServiceProtocolProtos.IdentityService
        .newReflectiveBlockingService(translator);
    BlockingService secretsProtocolService = SecretsProtocolProtos.IdentitySecretsService
        .newReflectiveBlockingService(translator);

    InetSocketAddress bindAddr = getAddress(conf);
    this.server = new RPC.Builder(conf)
        .setProtocol(IdentityServiceProtocolPB.class)
        .setInstance(identityProtocolService)
        .setBindAddress(bindAddr.getHostName())
        .setPort(bindAddr.getPort())
        .setNumHandlers(conf.getInt(
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_LISTENER_THREAD_COUNT_KEY,
            HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_LISTENER_THREAD_COUNT_DEFAULT))
        .setVerbose(false).build();
    addPBProtocol(conf, SecretsProtocolPB.class, secretsProtocolService, server);

    // set service-level authorization security policy
    if (conf.getBoolean(CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, false)) {
      server.refreshServiceAcl(conf, policy);
    }

  }

  void addPBProtocol(Configuration conf, Class<?> protocol, BlockingService service,
      RPC.Server server) throws IOException {
    RPC.setProtocolEngine(conf, protocol, ProtobufRpcEngine.class);
    server.addProtocol(RPC.RpcKind.RPC_PROTOCOL_BUFFER, protocol, service);
  }

  public void start() {
    this.server.start();
  }

  public boolean isAlive() {
    return server != null;
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

  private static InetSocketAddress getAddress(Configuration conf) {
    String addr = conf.get(
        CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_DEFAULT);
    return NetUtils.createSocketAddr(addr,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_PORT_DEFAULT,
        CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY);
  }

  @Override
  public IdentityResponse authenticate(IdentityRequest request) throws IOException {
    return identityService.authenticate(request);
  }

  @Override
  public Secrets getSecrets(byte[] identityToken, String protocol) throws IOException {
    return identityService.getSecrets(identityToken, protocol);
  }

  @Override
  public byte[] renewToken(byte[] identityToken, long tokenId) throws IOException {
    return identityService.renewToken(identityToken, tokenId);
  }

  @Override
  public void cancelToken(byte[] identityToken, long tokenId) throws IOException {
    identityService.cancelToken(identityToken, tokenId);
  }
}
