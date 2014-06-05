package org.apache.hadoop.security.tokenauth.has;

import java.io.IOException;
import java.net.HttpURLConnection;

import javax.ws.rs.core.Response;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.security.tokenauth.token.InvalidTokenException;
import org.apache.hadoop.security.tokenauth.token.TokenAccessDeniedException;

/**
 * A collection of REST util methods
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class RestUtil {
  /**
   * Create a HTTP response with status 403
   * @param message the content of the response
   * @return
   */
  public static Response createForbiddenResponse(String message) {
    return Response.status(HttpURLConnection.HTTP_FORBIDDEN).build();
  }

  /**
   * Handle exceptions. If it is a permission related exception, a HTTP
   * response with correct status will returned. Otherwise, throw this
   * exception.
   * @param e
   * @return A HTTP response with correct status.
   * @throws IOException 
   */
  public static Response handleException(IOException e) throws IOException{
    if (e instanceof InvalidTokenException || e instanceof TokenAccessDeniedException) {
      return createForbiddenResponse(e.getMessage());
    }
    else{
      throw new IOException(e);
    }
  }
}
