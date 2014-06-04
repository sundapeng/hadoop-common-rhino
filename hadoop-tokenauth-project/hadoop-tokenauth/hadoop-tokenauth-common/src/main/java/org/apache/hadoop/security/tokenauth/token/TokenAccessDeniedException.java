package org.apache.hadoop.security.tokenauth.token;

import java.io.IOException;

public class TokenAccessDeniedException extends IOException {

  private static final long serialVersionUID = 1L;

  public TokenAccessDeniedException(){
    super();
  }

  public TokenAccessDeniedException(String message){
    super(message);
  }
}
