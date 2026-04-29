import java.nio.file.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MonitoredProgram2 {
  public static void main(String[] args) throws IOException {
    Path p = Paths.get("test.txt").toAbsolutePath();
    Files.write(p, "Hello World\nMore data\n".getBytes(StandardCharsets.UTF_8));
    System.out.println("Fichier créé ici: " + p);
  }
}
