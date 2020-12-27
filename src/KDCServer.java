import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.util.ArrayList;
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

  public static void main(String[] args) {
    try {
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

      ServerSocket serverSocket = new ServerSocket(3000);
      System.out.println("KDC server listening on port " + serverSocket.getLocalPort());
      ArrayList<ClientHandler> threads = new ArrayList<>();
      // Generate 32 char byte random password
      Random random = new Random();
      String password = random.ints(48, 122 + 1).filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)).limit(32)
          .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(password.getBytes());
        byte[] hashedPassword = md.digest();
        byte[] encodedHash = Base64.getEncoder().encode(hashedPassword);
        new File("passwd").createNewFile();
        Files.write(new File("passwd").toPath(), encodedHash, StandardOpenOption.WRITE);
        new File("kdclog").createNewFile();
        Files.write(new File("kdclog").toPath(), password.getBytes(), StandardOpenOption.WRITE);
      } catch (NoSuchAlgorithmException ex) {
        ex.printStackTrace();
      }
      // Create keystores if missing
      String[] keys = { "client", "kdc", "web", "mail", "database" };
      File keystoreDir = new File("keystore");
      if (!keystoreDir.exists()) {
        keystoreDir.mkdir();
      }
      File unsignedCertDir = new File("unsignedCerts");
      if (!unsignedCertDir.exists()) {
        unsignedCertDir.mkdir();
      }
      File signedCertDir = new File("cert");
      if (!signedCertDir.exists()) {
        signedCertDir.mkdir();
      }
      File keysDir = new File("keys");
      if (!keysDir.exists()) {
        keysDir.mkdir();
      }

      for (String alias : keys) {
        if (!Files.exists(Paths.get("keystore/" + alias + ".jks"))) {
          String[] keyGenArgs = { "keytool", "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keystore",
              "keystore/" + alias + ".jks", "-dname", "CN=BBM463", "-storetype", "JKS", "-keypass", "password",
              "-storepass", "password", "-validity", "365", "-keysize", "2048" };
          try {
            Process p = Runtime.getRuntime().exec(keyGenArgs);
            p.waitFor();
          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }
        if (!Files.exists(Paths.get("unsignedCerts/" + alias + ".cer"))) {
          String[] exportCertArgs = { "keytool", "-export", "-alias", alias, "-keystore", "keystore/" + alias + ".jks",
              "-rfc", "-keypass", "password", "-storepass", "password", "-file", "unsignedCerts/" + alias + ".cer" };
          try {
            Process p = Runtime.getRuntime().exec(exportCertArgs);
            p.waitFor();
          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }

        if (!Files.exists(Paths.get("keys/" + alias))) {
          try {
            FileInputStream fis = new FileInputStream("keystore/" + alias + ".jks");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, "password".toCharArray());
            PrivateKey key = (PrivateKey) keystore.getKey(alias, "password".toCharArray());
            byte[] encodedPrivateKey = Base64.getEncoder().encode(key.getEncoded());
            Files.write(Paths.get("keys/" + alias), encodedPrivateKey);
          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }
      }
      // Read the private key from keystore
      try {
        FileInputStream fis = new FileInputStream("keystore/kdc.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "password".toCharArray());
        privKey = (PrivateKey) keystore.getKey("kdc", "password".toCharArray());
        for (String alias : keys) {
          // Read the certificate from cer file and sign the content
          if (!Files.exists(Paths.get("cert/" + alias + ".cer"))) {
            try {
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
              }
            } catch (Exception ex) {
              ex.printStackTrace();
            }
          }
        }
      } catch (Exception ex) {
        ex.printStackTrace();
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
        Thread.currentThread();
        while (!Thread.interrupted()) {
          try {
            ClientHandler ch = new ClientHandler(serverSocket.accept());
            threads.add(ch);
            ch.start();
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
      // Server closing sequence
      for (ClientHandler t : threads) { // Stop client threads.
        t.disconnect();
        t.interrupt();
      }
      // Close remaining threads sockets etc.
      reception.interrupt();
      sc.close();
      serverSocket.close();
    } catch (Exception e) {
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

  private static class ClientHandler extends Thread {
    private Socket clientSocket;
    private DataInputStream dis;
    private DataOutputStream dos;

    public ClientHandler(Socket socket) {
      this.clientSocket = socket;
    }

    public void disconnect() {
      try {
        dis.close();
        dos.close();
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }

    public void run() {
      try {
        this.dis = new DataInputStream(clientSocket.getInputStream());
        this.dos = new DataOutputStream(clientSocket.getOutputStream());

        // Size of message length can be made static later !!
        // Receive first message
        int clientNameLength = dis.readInt();
        byte[] clientNameBytes = new byte[clientNameLength];
        dis.readFully(clientNameBytes);
        int encryptedContentLength = dis.readInt();
        byte[] encryptedContent = new byte[encryptedContentLength];
        dis.readFully(encryptedContent);
        String[] secondParts = new String(decrypt(encryptedContent, privKey)).split(",");

        // Send second message
        // First part of the second message
        Date timeStampTwo = new Date();
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey sessionKey = kg.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
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
        String ticketContent = secondParts[0] + "," + secondParts[2] + "," + timeStampTwo.toString()+ "," + encodedKey;
        byte[] ticketEncrypted = encrypt(ticketContent.getBytes(), serverKey);

        dos.writeInt(firstPartEncrypted.length);
        dos.write(firstPartEncrypted);
        dos.writeInt(ticketEncrypted.length);
        dos.write(ticketEncrypted);

        System.out.println(Base64.getEncoder().encodeToString(firstPartEncrypted));
        System.out.println(Base64.getEncoder().encodeToString(ticketEncrypted));

      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }
}
