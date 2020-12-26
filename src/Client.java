import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

// Alice
public class Client {
  private static Socket socket;

  public static void main(String[] args) {
    try {
      byte[] hashedPassword = Files.readAllBytes(new File("passwd").toPath());
      Scanner sc = new Scanner(System.in);
      System.out.println("Enter password");
      while (!verifyPassword(sc.nextLine(),hashedPassword)) {
        System.out.println("Enter password");
      }
      sc.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
    connect(3000);
  }

  private static void connect(int portNumber) {
    try {
      socket = new Socket("localhost", portNumber);

      System.out.println("Connected to " + portNumber);

      Thread t = new Thread(() -> {
        System.out.println("running");
      });
      t.start();
    } catch (IOException e) {
      System.out.println("Couldnt connect!");
      e.printStackTrace();
    }
  }

  // verify password by comparing hashes
  private static boolean verifyPassword(String password,byte[] hashedPassword) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(password.getBytes());
      byte[] passwordDigest = md.digest();
      System.out.println(new String(hashedPassword));
      byte[] decodedHash = Base64.getDecoder().decode(hashedPassword);
      System.out.println(new String(decodedHash));

      if(Arrays.equals(decodedHash,passwordDigest)){
        return true;
      }else{
        return false;
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }
}
