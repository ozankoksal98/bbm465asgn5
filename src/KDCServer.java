import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class KDCServer {
  public static void main(String[] args) {
    try {
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
        PrivateKey key = (PrivateKey) keystore.getKey("kdc", "password".toCharArray());
        for (String alias : keys) {
          // Read the certificate from cer file and sign the content
          if (!Files.exists(Paths.get("cert/" + alias + ".cer"))) {
            try {
              if (key instanceof PrivateKey) {
                byte[] certBytes = Files.readAllBytes(Paths.get("unsignedCerts/" + alias + ".cer"));
                Signature sig = Signature.getInstance("SHA1WithRSA");
                sig.initSign(key);
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
    } catch (IOException e) {
      e.printStackTrace();

    }
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
        int messageOneLength = dis.readInt();
        byte[] messageOne = new byte[messageOneLength];
        dis.readFully(messageOne);

      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
