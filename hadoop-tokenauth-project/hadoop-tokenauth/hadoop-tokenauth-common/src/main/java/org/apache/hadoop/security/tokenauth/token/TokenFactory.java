package org.apache.hadoop.security.tokenauth.token;

import java.io.IOException;

import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.impl.DefaultTokenFactory;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;

public abstract class TokenFactory {
  private static TokenFactory instance;
  
  public static TokenFactory get() {
    if (instance == null) {
      synchronized(TokenFactory.class) {
        if (instance == null) {
          instance = new DefaultTokenFactory();
        }
      }
    }
    
    return instance;
  }
  
  /** only for read **/
  public abstract Token createToken(byte[] token) throws IOException;
  
  /**
   * This method is used in client side, when creating 
   * identity token from bytes and there is no validation secrets.
   */
  public abstract IdentityToken createIdentityToken(byte[] identityToken) throws IOException;
  
  /**
   * Create identity token, and verify it using secrets.
   */
  public abstract IdentityToken createIdentityToken(Secrets secrets, byte[] identityToken) throws IOException;
  
  /**
   * This method is used in client side, when creating 
   * access token from bytes and there is no validation secrets.
   */
  public abstract Token createAccessToken(byte[] accessToken) throws IOException;
  
  /**
   * Create access token, and verify it using secrets.
   */
  public abstract Token createAccessToken(Secrets secrets, byte[] accessToken) throws IOException;
}
