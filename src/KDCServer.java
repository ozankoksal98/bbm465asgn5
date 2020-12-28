import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KDCServer {
  private static Cipher cipher;
  private static PrivateKey privKey;
  private static DataInputStream dis;
  private static DataOutputStream dos;

  public static void main(String[] args) {
    try {
      BufferedWriter log = new BufferedWriter(new FileWriter("kdclog"));
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      ServerSocket serverSocket = new ServerSocket(3000);
      // Generate 32 char byte random password
      Random random = new Random();
      String password = random.ints(48, 122 + 1).filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)).limit(32)
          .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
      try {
        // Hash the password and store it
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(password.getBytes());
        byte[] hashedPassword = md.digest();
        byte[] encodedHash = Base64.getEncoder().encode(hashedPassword);
        log.write("Created 32 char random password : " + password + "\n");
        new File("passwd").createNewFile();
        Files.write(new File("passwd").toPath(), encodedHash, StandardOpenOption.WRITE);
        log.write("Password saved to the passwd file encoded in Base64.\n");
        log.flush();
      } catch (NoSuchAlgorithmException ex) {
        ex.printStackTrace();
      }
      // Create keystores, certs
      String[] keys = { "client", "kdc", "Web", "Mail", "Database" };
      File keystoreDir = new File("keystore");
      if (!keystoreDir.exists()) {
        keystoreDir.mkdir();
        log.write("Keystore directory created.\n");
      }
      File unsignedCertDir = new File("unsignedCerts");
      if (!unsignedCertDir.exists()) {
        unsignedCertDir.mkdir();
      }
      File signedCertDir = new File("cert");
      if (!signedCertDir.exists()) {
        signedCertDir.mkdir();
        log.write("Cert directory created.\n");
      }
      File keysDir = new File("keys");
      if (!keysDir.exists()) {
        keysDir.mkdir();
        log.write("Keys directory created.\n");
      }

      for (String alias : keys) {
        if (!Files.exists(Paths.get("keystore/" + alias + ".jks"))) {
          String[] keyGenArgs = { "keytool", "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keystore",
              "keystore/" + alias + ".jks", "-dname", "CN=BBM463", "-storetype", "JKS", "-keypass", "password",
              "-storepass", "password", "-validity", "365", "-keysize", "2048" };
          Process p = Runtime.getRuntime().exec(keyGenArgs);
          p.waitFor();
          if (alias.equals("client")) {
            log.write("Keystore for " + alias + " created.\n");
          } else {
            log.write("Keystore for " + alias + " server created.\n");
          }
        }
        if (!Files.exists(Paths.get("unsignedCerts/" + alias + ".cer"))) {
          String[] exportCertArgs = { "keytool", "-export", "-alias", alias, "-keystore", "keystore/" + alias + ".jks",
              "-rfc", "-keypass", "password", "-storepass", "password", "-file", "unsignedCerts/" + alias + ".cer" };
          Process p = Runtime.getRuntime().exec(exportCertArgs);
          p.waitFor();
          if (alias.equals("client")) {
            log.write("Certificate file for " + alias + " created.\n");
          } else {
            log.write("Certificate file for " + alias + " server created.\n");
          }
        }

        if (!Files.exists(Paths.get("keys/" + alias))) {
          FileInputStream fis = new FileInputStream("keystore/" + alias + ".jks");
          KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
          keystore.load(fis, "password".toCharArray());
          PrivateKey key = (PrivateKey) keystore.getKey(alias, "password".toCharArray());
          byte[] encodedPrivateKey = Base64.getEncoder().encode(key.getEncoded());
          Files.write(Paths.get("keys/" + alias), encodedPrivateKey);
          if (alias.equals("client")) {
            log.write("Private key file for " + alias + " created.\n");
          } else {
            log.write("Private key file for " + alias + " server created.\n");
          }
        }
      }
      // Read the private key from keystore
      FileInputStream fis = new FileInputStream("keystore/kdc.jks");
      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(fis, "password".toCharArray());
      privKey = (PrivateKey) keystore.getKey("kdc", "password".toCharArray());
      log.write("Private key is read in from the keystore.\n");
      for (String alias : keys) {
        // Read the certificate from cer file and sign the content
        if (!Files.exists(Paths.get("cert/" + alias + ".cer"))) {
          if (privKey instanceof PrivateKey) {
            byte[] certBytes = Files.readAllBytes(Paths.get("unsignedCerts/" + alias + ".cer"));
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(privKey);
            sig.update(certBytes);
            byte[] sigBytes = sig.sign();
            ByteArrayOutputStream signedCert = new ByteArrayOutputStream();
            // Write to a new file inside cert directory
            // First line is the signature bytes in
            signedCert.write(Base64.getEncoder().encode(sigBytes));
            signedCert.write("\n".getBytes());
            signedCert.write(certBytes);
            FileOutputStream fos = new FileOutputStream(new File("cert/" + alias + ".cer"));
            signedCert.writeTo(fos);
            if (alias.equals("client")) {
              log.write("Certificate file for " + alias + " signed.\n");
            } else {
              log.write("Certificate file for " + alias + " server signed.\n");
            }
            log.write("Signature added to the first line of the file.\n");
          }
        }
      }
      for (String alias : keys) {
        File f = new File("unsignedCerts/" + alias + ".cer");
        if (f.exists()) {
          f.delete();
        }
      }
      File f = new File("unsignedCerts");
      if (f.exists()) {
        f.delete();
      }

      // Client receiving thread
      Thread reception = new Thread(() -> {
        try {
          log.write("------KDC server started listening on port " + serverSocket.getLocalPort() + ".------\n");
          log.flush();
        } catch (Exception ex) {
          ex.printStackTrace();
        }

        Thread.currentThread();
        while (!Thread.interrupted()) {
          try {
            Socket clientSocket = serverSocket.accept();
            log.write("New client connected.\n");
            dis = new DataInputStream(clientSocket.getInputStream());
            dos = new DataOutputStream(clientSocket.getOutputStream());

            // Size of message length can be made static later !!
            // Receive first message
            log.write("1) First message recieved.\n");
            int clientNameLength = dis.readInt();
            byte[] clientNameBytes = new byte[clientNameLength];
            dis.readFully(clientNameBytes);
            String clientName = new String(clientNameBytes);
            int encryptedContentLength = dis.readInt();
            byte[] encryptedContent = new byte[encryptedContentLength];
            dis.readFully(encryptedContent);
            String[] secondParts = new String(decrypt(encryptedContent, privKey)).split(",");
            log.write("1) Encrypted part of the first message decrypted with KDC`s private key(RKDC).\n");
            log.write(String.format("1) First message content : %s, PKDC(%s)\n", clientName, String.join(", ", secondParts)));
            // Send second message
            // First part of the second message
            Date timeStampTwo = new Date();
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey sessionKey = kg.generateKey();
            log.write("2) Session key (KA) generated.\n");
            String encodedKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
            log.write(String.format("2) Session key encoded in Base64 : %s\n" , encodedKey));
            String firstPart = encodedKey + "," + secondParts[2] + "," + timeStampTwo.toString();
            byte[] clientCertBytes = new String(Files.readAllBytes(Paths.get("cert/client.cer"))).split("\n", 2)[1]
                .getBytes();
            X509Certificate clientCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(clientCertBytes));
            PublicKey clientKey = clientCertificate.getPublicKey();
            byte[] serverCertBytes = new String(Files.readAllBytes(Paths.get("cert/" + secondParts[2] + ".cer")))
                .split("\n", 2)[1].getBytes();
            X509Certificate serverCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(serverCertBytes));
            PublicKey serverKey = serverCertificate.getPublicKey();
            byte[] firstPartEncrypted = encrypt(firstPart.getBytes(), clientKey);
            log.write("2) First part of the second message created and encrypted with clients public key.\n");
            log.write(String.format("2) First part : PA(%s, %s, %s)\n", clientName, secondParts[2], timeStampTwo.toString()));
            String ticketContent = secondParts[0] + "," + secondParts[2] + "," + timeStampTwo.toString() + ","
                + encodedKey;
            log.write("2) Second part of the first message 'ticket' created and encrypted with "+ secondParts[2] +" server`s public key.\n");
            log.write(String.format("2) Ticket : P%s(%s, %s, %s, %s)\n",secondParts[2] ,secondParts[0], secondParts[2], timeStampTwo.toString(), encodedKey));
            byte[] ticketEncrypted = encrypt(ticketContent.getBytes(), serverKey);
            System.out.println(secondParts[2]);

            dos.writeInt(firstPartEncrypted.length);
            dos.write(firstPartEncrypted);
            dos.writeInt(ticketEncrypted.length);
            dos.write(ticketEncrypted);
            log.write(String.format("2) Second message content : PA(%s, %s, %s), Ticket\n", clientName, secondParts[2], timeStampTwo.toString()));
            log.write("2) Second message sent.\n");
            dis.close();
            dos.close();
            clientSocket.close();
            log.flush();
          } catch (SocketException se) {

          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }

      });
      reception.start();

      // Current thread listens for command line inputs
      Scanner sc = new Scanner(System.in);
      String close;
      while (true) {
        close = sc.nextLine();
        if (close.equals("close")) {
          break;
        }
      }
      // Close remaining threads sockets etc.
      log.close();
      reception.interrupt();
      sc.close();
      serverSocket.close();
    } catch (

    Exception e) {
      e.printStackTrace();

    }
  }

  private static byte[] encrypt(byte[] content, Key key) throws Exception {
    cipher.init(1, key);
    return cipher.doFinal(content);
  }

  private static byte[] decrypt(byte[] content, Key key) throws Exception {
    cipher.init(2, key);
    return cipher.doFinal(content);
  }
}
