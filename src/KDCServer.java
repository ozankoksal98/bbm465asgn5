import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
      for (String key : keys) {
        if (!Files.exists(Paths.get("keystore/" + key + ".jks"))) {
          String[] keytoolArgs = new String[] { "keytool", "-genkeypair", "-alias", key, "-keyalg", "RSA", "-keystore",
              "keystore/" + key + ".jks", "-dname", "CN=BBM463", "-storetype", "JKS", "-keypass", "password",
              "-storepass", "password", "-validity", "365", "-keysize", "2048" };
          try {
            Process p = Runtime.getRuntime().exec(keytoolArgs);
            p.waitFor();
            BufferedReader buf = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            while ((line = buf.readLine()) != null) {
              System.out.println(line);
            }
          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }
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
