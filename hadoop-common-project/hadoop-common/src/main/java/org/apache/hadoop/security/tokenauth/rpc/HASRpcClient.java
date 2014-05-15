package org.apache.hadoop.security.tokenauth.rpc;

import java.io.IOException;
import java.net.InetSocketAddress;

import javax.net.SocketFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.tokenauth.api.AuthorizationServiceProtocol;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.IdentityServiceProtocol;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.has.WrappedSocketFactory;
import org.apache.hadoop.security.tokenauth.rpc.pb.AuthorizationServiceProtocolClientSideTranslatorPB;
import org.apache.hadoop.security.tokenauth.rpc.pb.IdentityServiceProtocolClientSideTranslatorPB;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

public class HASRpcClient extends HASClient {

  private Configuration conf;
  private IdentityServiceProtocol identityService;
  private AuthorizationServiceProtocol authorizationService;

  public HASRpcClient() {
    this.conf = new Configuration();
    initialize();
  }

  public HASRpcClient(Configuration conf) {
    this.conf = conf == null ? new Configuration() : new Configuration(conf);
    initialize();
  }

  void initialize() {
    conf.setBoolean(CommonConfigurationKeys.IPC_CLIENT_FALLBACK_TO_SIMPLE_AUTH_ALLOWED_KEY, true);
  }

  @Override
  public IdentityResponse authenticate(IdentityRequest request)
      throws IOException {
    ensureConnectIdentityServer();
    return identityService.authenticate(request);
  }

  @Override
  protected byte[] doGetAccessToken(byte[] identityToken, String protocol)
      throws IOException {
    ensureConnectAuthorizationServer();
    return authorizationService.getAccessToken(identityToken, protocol);
  }

  @Override
  public Token renewToken(Token identityToken) throws IOException {
    ensureConnectIdentityServer();
    byte[] newIdentityToken = identityService.renewToken(
        TokenUtils.getBytesOfToken(identityToken), identityToken.getId());

    return TokenFactory.get().createIdentityToken(newIdentityToken);
  }

  @Override
  public void cancelToken(Token identityToken) throws IOException {
    ensureConnectIdentityServer();
    identityService.cancelToken(TokenUtils.getBytesOfToken(identityToken),
        identityToken.getId());
  }

  void ensureConnectIdentityServer() throws IOException {
    if (identityService == null) {
      synchronized (this) {
        if (identityService == null) {
          InetSocketAddress address = NetUtils.createSocketAddr(
              conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY),
              0,
              CommonConfigurationKeysPublic.HADOOP_SECURITY_IDENTITY_SERVER_RPC_ADDRESS_KEY);
          identityService = new IdentityServiceProtocolClientSideTranslatorPB(
              conf, address, getSocketFactory(), 15000);
        }
      }
    }
  }

  void ensureConnectAuthorizationServer() throws IOException {
    if (authorizationService == null) {
      synchronized (this) {
        if (authorizationService == null) {
          InetSocketAddress address = NetUtils.createSocketAddr(
              conf.get(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY),
              0,
              CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHORIZATION_SERVER_RPC_ADDRESS_KEY);
          AuthorizationServiceProtocol authzProtocols = new AuthorizationServiceProtocolClientSideTranslatorPB(
              conf, address, getSocketFactory(), 15000);
          authorizationService = authzProtocols;
        }
      }
    }
  }

  SocketFactory getSocketFactory() {
    SocketFactory factory = NetUtils.getDefaultSocketFactory(conf);
    return new WrappedSocketFactory(factory);
  }

}
