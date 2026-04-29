import java.io.FileInputStream;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import ca.uqac.lif.cep.Pullable;
import ca.uqac.lif.cep.io.ReadLines;

public class MonitorSIEMAdvanced
{
  static class Event
  {
    LocalDateTime timestamp;
    String type;
    Map<String, String> fields = new HashMap<String, String>();
  }

  static class AttackState
  {
    int failedCount = 0;
    LocalDateTime firstFailedTs = null;
    LocalDateTime suspiciousSuccessTs = null;
    boolean compromiseAlertRaised = false;
    boolean exfiltrationAlertRaised = false;

    void resetFailures()
    {
      failedCount = 0;
      firstFailedTs = null;
    }
  }

  public static void main(String[] args) throws Exception
  {
    ReadLines reader = new ReadLines(new FileInputStream("siem_advanced.log"));
    Pullable p = reader.getPullableOutput();

    // Etat suivi par couple user|ip
    Map<String, AttackState> states = new HashMap<String, AttackState>();

    while (p.hasNext())
    {
      String line = (String) p.pull();
      System.out.println("Log lu : " + line);

      Event e = parseLine(line);
      if (e == null)
      {
        continue;
      }

      String user = e.fields.get("user");
      String ip = e.fields.get("ip");

      // Certains événements peuvent ne pas avoir user/ip
      if (user == null || ip == null)
      {
        continue;
      }

      String key = user + "|" + ip;
      AttackState st = states.get(key);
      if (st == null)
      {
        st = new AttackState();
        states.put(key, st);
      }

      // Nettoyage des fenêtres temporelles
      if (st.firstFailedTs != null)
      {
        long minutes = Duration.between(st.firstFailedTs, e.timestamp).toMinutes();
        if (minutes > 10)
        {
          st.resetFailures();
        }
      }

      if (st.suspiciousSuccessTs != null)
      {
        long minutes = Duration.between(st.suspiciousSuccessTs, e.timestamp).toMinutes();
        if (minutes > 5)
        {
          st.suspiciousSuccessTs = null;
          st.compromiseAlertRaised = false;
          st.exfiltrationAlertRaised = false;
        }
      }

      // Corrélation SIEM
      if (e.type.equals("LOGIN_FAILED"))
      {
        if (st.firstFailedTs == null)
        {
          st.firstFailedTs = e.timestamp;
          st.failedCount = 1;
        }
        else
        {
          long minutes = Duration.between(st.firstFailedTs, e.timestamp).toMinutes();
          if (minutes <= 10)
          {
            st.failedCount++;
          }
          else
          {
            st.firstFailedTs = e.timestamp;
            st.failedCount = 1;
          }
        }
      }
      else if (e.type.equals("LOGIN_SUCCESS"))
      {
        if (st.firstFailedTs != null)
        {
          long minutes = Duration.between(st.firstFailedTs, e.timestamp).toMinutes();
          if (st.failedCount >= 3 && minutes <= 10)
          {
            st.suspiciousSuccessTs = e.timestamp;
            System.out.println("⚠ ALERTE NIVEAU 1 : login suspect après " +
                st.failedCount + " échecs pour user=" + user + " ip=" + ip);
          }
        }
        st.resetFailures();
      }
      else if (e.type.equals("FILE_ACCESS"))
      {
        if (st.suspiciousSuccessTs != null)
        {
          long minutes = Duration.between(st.suspiciousSuccessTs, e.timestamp).toMinutes();
          String file = e.fields.get("file");
          if (minutes <= 5 && isSensitiveFile(file) && !st.compromiseAlertRaised)
          {
            System.out.println("⚠ ALERTE NIVEAU 2 : accès sensible après login suspect -> user="
                + user + " ip=" + ip + " file=" + file);
            st.compromiseAlertRaised = true;
          }
        }
      }
      else if (e.type.equals("COMMAND_EXEC"))
      {
        if (st.suspiciousSuccessTs != null)
        {
          long minutes = Duration.between(st.suspiciousSuccessTs, e.timestamp).toMinutes();
          String cmd = e.fields.get("cmd");
          if (minutes <= 5 && isSuspiciousCommand(cmd) && !st.compromiseAlertRaised)
          {
            System.out.println("⚠ ALERTE NIVEAU 2 : commande suspecte après login suspect -> user="
                + user + " ip=" + ip + " cmd=" + cmd);
            st.compromiseAlertRaised = true;
          }
        }
      }
      else if (e.type.equals("OUTBOUND_CONNECT"))
      {
        if (st.suspiciousSuccessTs != null)
        {
          long minutes = Duration.between(st.suspiciousSuccessTs, e.timestamp).toMinutes();
          String dst = e.fields.get("dst");
          if (minutes <= 5 && isExternalDestination(dst) && !st.exfiltrationAlertRaised)
          {
            System.out.println("🚨 ALERTE NIVEAU 3 : possible exfiltration ou C2 -> user="
                + user + " ip=" + ip + " dst=" + dst);
            st.exfiltrationAlertRaised = true;
          }
        }
      }
    }
  }

  static Event parseLine(String line)
  {
    try
    {
      String[] parts = line.split(" ");
      if (parts.length < 2)
      {
        return null;
      }

      Event e = new Event();
      e.timestamp = LocalDateTime.parse(parts[0]);
      e.type = parts[1];

      for (int i = 2; i < parts.length; i++)
      {
        String part = parts[i];
        int idx = part.indexOf('=');
        if (idx > 0)
        {
          String key = part.substring(0, idx);
          String value = part.substring(idx + 1);
          e.fields.put(key, value);
        }
      }
      return e;
    }
    catch (Exception ex)
    {
      return null;
    }
  }

  static boolean isSensitiveFile(String file)
  {
    if (file == null)
    {
      return false;
    }
    return file.equals("/etc/shadow")
        || file.equals("/etc/passwd")
        || file.equals("secrets.txt");
  }

  static boolean isSuspiciousCommand(String cmd)
  {
    if (cmd == null)
    {
      return false;
    }
    return cmd.contains("curl")
        || cmd.contains("wget")
        || cmd.contains("nc")
        || cmd.contains("powershell");
  }

  static boolean isExternalDestination(String dst)
  {
    if (dst == null)
    {
      return false;
    }
    // Version simple : on considère qu'une IP 198.* ou 203.* est externe
    return dst.startsWith("198.") || dst.startsWith("203.");
  }
}