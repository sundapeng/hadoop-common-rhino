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

package org.apache.hadoop.security.tokenauth.has.protocolPB;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import javax.net.SocketFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.ProtobufHelper;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.ProtocolTranslator;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.has.protocol.SecretsProtocol;
import org.apache.hadoop.security.tokenauth.proto.SecretsProtocolProtos;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;

import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;

public class SecretsProtocolClientSideTranslatorPB
    implements Closeable, ProtocolTranslator, SecretsProtocol {

  private final SecretsProtocolPB rpcProxy;

  private final static RpcController NULL_CONTROLLER = null;

  public SecretsProtocolClientSideTranslatorPB(Configuration conf,
      InetSocketAddress address, SocketFactory socketFactory, int timeout) 
      throws IOException {
    RPC.setProtocolEngine(conf, SecretsProtocolPB.class, ProtobufRpcEngine.class);
    rpcProxy = RPC.getProxy(SecretsProtocolPB.class,
        RPC.getProtocolVersion(SecretsProtocolPB.class), address,
        UserGroupInformation.createRemoteUser("HASClient"), conf, socketFactory, timeout);
  }

  @Override
  public void close() throws IOException {
    RPC.stopProxy(rpcProxy);
  }

  @Override
  public Object getUnderlyingProxyObject() {
    return rpcProxy;
  }

  @Override
  public Secrets getSecrets(byte[] identityToken, String protocol) throws
      IOException {
    try {
      SecretsProtocolProtos.GetSecretsRequestProto proto =
          PBHelper.convert(identityToken, protocol);
      return PBHelper.convert(rpcProxy.getSecrets(NULL_CONTROLLER, proto));
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    } catch (InvalidKeyException e) {
      throw ProtobufHelper.getRemoteException(new ServiceException(e));
    }
  }
}
