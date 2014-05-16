package org.apache.hadoop.security.tokenauth.token;

import java.io.IOException;

public class InvalidTokenException extends IOException {

  private static final long serialVersionUID = 1L;
  
  public InvalidTokenException(String msg) {
    super(msg);
  }
  
}
