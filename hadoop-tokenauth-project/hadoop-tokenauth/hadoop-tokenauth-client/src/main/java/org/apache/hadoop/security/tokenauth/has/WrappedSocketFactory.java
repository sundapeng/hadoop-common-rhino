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

package org.apache.hadoop.security.tokenauth.has;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

public class WrappedSocketFactory extends SocketFactory {
  private SocketFactory socketFactory;
  
  public WrappedSocketFactory(SocketFactory socketFactory) {
    this.socketFactory = socketFactory;
  }

  @Override
  public Socket createSocket() throws IOException {
    return socketFactory.createSocket();
  }
  
  @Override
  public Socket createSocket(InetAddress addr, int port) throws IOException {
    return socketFactory.createSocket(addr, port);
  }
  
  @Override
  public Socket createSocket(InetAddress addr, int port,
      InetAddress localHostAddr, int localPort) throws IOException {
    return socketFactory.createSocket(addr, port, localHostAddr, localPort);
  }
  
  @Override
  public Socket createSocket(String host, int port) 
      throws IOException, UnknownHostException {
    return socketFactory.createSocket(host, port);
  }
  
  @Override
  public Socket createSocket(String host, int port,
      InetAddress localHostAddr, int localPort) 
      throws IOException, UnknownHostException {
    return socketFactory.createSocket(host, port, localHostAddr, localPort);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result
        + ((socketFactory == null) ? 0 : socketFactory.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    WrappedSocketFactory other = (WrappedSocketFactory) obj;
    if (socketFactory == null) {
      if (other.socketFactory != null)
        return false;
    } else if (!socketFactory.equals(other.socketFactory))
      return false;
    return true;
  }
}
