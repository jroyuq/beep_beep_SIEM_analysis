import java.io.FileInputStream;

import ca.uqac.lif.cep.Pullable;
import ca.uqac.lif.cep.io.ReadLines;

public class MonitorAlert {
  public static void main(String[] args) throws Exception {
    ReadLines reader = new ReadLines(new FileInputStream("test.txt"));
    Pullable p = reader.getPullableOutput();

    while (p.hasNext()) {
      String line = (String) p.pull();
      System.out.println("Ligne lue : " + line);

      if (line.contains("More")) {
        System.out.println("⚠ ALERTE : contenu surveillé détecté !");
      }
    }
  }
}