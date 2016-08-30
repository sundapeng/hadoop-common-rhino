package org.apache.hadoop.security.tokenauth.api.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;
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
  
  public static String doHttpConnect(URL url, String content, String requestMethod,
      String contentType, String acceptType) throws IOException {
    return doHttpConnect(url, content, requestMethod, contentType, acceptType,
        HttpURLConnection.HTTP_OK);
  }

  public static String doHttpConnect(URL url, String content, String requestMethod,
      String contentType, String acceptType, int expectedStatus) throws IOException {
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    String result = "";
    if (conn != null) {
      conn.setDoOutput(true);
      conn.setRequestMethod(requestMethod);
      conn.setRequestProperty("Accept", acceptType);
      conn.setRequestProperty("charset", "utf-8");
      if (content != null) {
        conn.setRequestProperty("Content-Type", contentType);
        conn.setRequestProperty("Content-Length",
            "" + String.valueOf(content.getBytes().length));
      }
      
      result = (content != null ? sendRequest(conn, content.getBytes(), expectedStatus) :
        sendRequest(conn, null, expectedStatus));
      
      conn.disconnect();
    }
    
    return result;
  }

  private static String sendRequest(HttpURLConnection conn, byte[] content,
      int expectedStatus) throws IOException {
    if (content != null) {
      OutputStream out = conn.getOutputStream();
      out.write(content);
      out.flush();
      out.close();
    }

    int httpStatus = conn.getResponseCode();
    if (expectedStatus != httpStatus) {
      throw new IOException("Server at " + conn
          .getURL() + " returned non ok status:" + httpStatus + ", message:" + conn
          .getResponseMessage());
    }
    
    InputStream in;
    if(HttpURLConnection.HTTP_OK == httpStatus){
      in = conn.getInputStream();
    }
    else{
      in = conn.getErrorStream();
    }
    String result = IOUtils.toString(in);
    if (in != null)
      in.close();
    return result;
  }
}
