import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import ca.uqac.lif.cep.Pullable;
import ca.uqac.lif.cep.io.ReadLines;

public class MonitorSIEM
{
  public static void main(String[] args) throws Exception
  {
    ReadLines reader = new ReadLines(new FileInputStream("siem.log"));
    Pullable p = reader.getPullableOutput();

    // Compteur d'échecs par IP
    Map<String, Integer> failedByIp = new HashMap<String, Integer>();

    while (p.hasNext())
    {
      String line = (String) p.pull();
      System.out.println("Log lu : " + line);

      if (line.contains("LOGIN_FAILED"))
      {
        String ip = extractField(line, "ip");
        if (ip != null)
        {
          int count = failedByIp.getOrDefault(ip, 0) + 1;
          failedByIp.put(ip, count);

          if (count == 5)
          {
            System.out.println("⚠ ALERTE SIEM : suspicion de brute force depuis l'IP " + ip);
          }
        }
      }
      else if (line.contains("LOGIN_SUCCESS"))
      {
        String ip = extractField(line, "ip");
        if (ip != null)
        {
          failedByIp.put(ip, 0);
        }
      }
    }
  }

  public static String extractField(String line, String fieldName)
  {
    String[] parts = line.split(" ");
    for (String part : parts)
    {
      if (part.startsWith(fieldName + "="))
      {
        return part.substring((fieldName + "=").length());
      }
    }
    return null;
  }
}