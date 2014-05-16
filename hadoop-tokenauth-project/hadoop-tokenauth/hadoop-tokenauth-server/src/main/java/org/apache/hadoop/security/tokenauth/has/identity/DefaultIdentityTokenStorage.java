package org.apache.hadoop.security.tokenauth.has.identity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;

public class DefaultIdentityTokenStorage extends IdentityTokenStorage {

  private Map<Long, IdentityTokenInfo> tokens;
  private String tokenFilePath; // the path to store issued tokens
  private Thread persistentThread;
  private long persistentInterval;
  public static final Log LOG = LogFactory.getLog(DefaultIdentityTokenStorage.class);

  public DefaultIdentityTokenStorage(Configuration conf) throws IllegalArgumentException, ClassNotFoundException, IOException {
    tokens = new HashMap<Long, IdentityTokenInfo>();
    tokenFilePath = conf
        .get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ISSUEDTOKENS_PERSISTENT_FILE_KEY);
    persistentInterval = conf.getLong(
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ISSUEDTOKENS_PERSISTENT_INTERVAL,
        3600) * 1000;
    // make sure the persistent file is accessible
    File tokenFile=new File(tokenFilePath);
    if (!((tokenFile.exists()&&tokenFile.canRead()&&tokenFile.canWrite())||(!tokenFile.exists())&&tokenFile.getParentFile().canWrite())){
      throw new IllegalArgumentException(
          "Cannot read or write issued tokens file. Please make sure you have set the right value for"
              + HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_ISSUEDTOKENS_PERSISTENT_FILE_KEY);
    }
    // try to recovery issued tokens from disk
    if(tokenFile.exists()){
      readFromDisk();
    }
    
    persistentThread=new Thread(new Runnable(){
      public void run(){
        while(true){
          cleanExpiredTokens();
          try {
            writeToDisk();
          } catch (IOException e) {
            LOG.error("Failed to persistent issued tokens.");
            LOG.error(e.getMessage());
          }
          try {
            Thread.sleep(persistentInterval);
          } catch (InterruptedException e) {
            LOG.error("Failed to sleep persistent thread.");
            LOG.error(e.getMessage());
          }
        }
      }
    });
    persistentThread.setDaemon(true);
    persistentThread.start();
    
    Runtime.getRuntime().addShutdownHook(new Thread(new Runnable(){
      public void run(){
        cleanExpiredTokens();
        try {
          writeToDisk();
        } catch (IOException e) {
          LOG.error("Failed to persistent issued tokens.");
          LOG.error(e.getMessage());
        }
        LOG.info("Persistented issued token before exit.");
      }
    }));
  }

  @Override
  public void put(IdentityTokenInfo tokenInfo) {
    tokens.put(tokenInfo.getId(), tokenInfo);
  }

  @Override
  public IdentityTokenInfo get(long tokenId) {
    return tokens.get(tokenId);
  }

  private void writeToDisk() throws IOException {
    synchronized(tokenFilePath){
      FileOutputStream stream = new FileOutputStream(tokenFilePath);
      ObjectOutputStream objectStream = new ObjectOutputStream(stream);
      objectStream.writeObject(tokens);
      objectStream.close();
    }
    LOG.debug("Wrote tokens to disk.");
  }

  private void readFromDisk() throws IOException, ClassNotFoundException {
    synchronized(tokenFilePath){
      FileInputStream stream = new FileInputStream(tokenFilePath);
      ObjectInputStream objectStream = new ObjectInputStream(stream);
      tokens = (Map<Long, IdentityTokenInfo>) objectStream.readObject();
      objectStream.close();
    }
    LOG.info("Recovered issued tokens from file.");
  }

  private void cleanExpiredTokens() {
    Iterator<Map.Entry<Long, IdentityTokenInfo>> iterator = tokens.entrySet().iterator();
    while (iterator.hasNext()) {
      Map.Entry<Long, IdentityTokenInfo> entry = iterator.next();
      if (entry.getValue().getExpirationTime() < System.currentTimeMillis()) {
        tokens.remove(entry.getKey());
      }
    }
  }
  
  @Override
  public void finalize(){
    LOG.debug("Identity storage is terminating.");
    try {
      writeToDisk();
    } catch (IOException e) {
      LOG.error("Failed to persistent issued tokens.");
      LOG.error(e.getMessage());
    }
  }
}
