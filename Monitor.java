import java.nio.file.*;
import java.io.IOException;
import java.util.List;

public class Monitor {

    public static void main(String[] args) throws IOException {

        Path p = Paths.get("test.txt");

        List<String> lines = Files.readAllLines(p);

        for(String line : lines) {

            if(line.contains("More")) {
                System.out.println("⚠ ALERT: suspicious content detected!");
            }

            System.out.println("Event: " + line);
        }
    }
}