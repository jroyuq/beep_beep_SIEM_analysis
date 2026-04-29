import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ca.uqac.lif.cep.Pullable;
import ca.uqac.lif.cep.io.ReadLines;

public class MonitorWazuhAuthLog
{
  // Compteurs SIEM simples par IP
  private static final Map<String, Integer> bruteForceCounter = new HashMap<String, Integer>();
  private static final Map<String, Integer> invalidUserCounter = new HashMap<String, Integer>();

  // Dernier utilisateur connecté avec succès par IP
  private static final Map<String, String> lastSuccessfulUserByIp = new HashMap<String, String>();

  // Regex utiles
  private static final Pattern ACCEPTED_PUBLICKEY =
      Pattern.compile("Accepted publickey for (\\S+) from ([0-9.]+)");

  private static final Pattern INVALID_USER =
      Pattern.compile("Invalid user (\\S+) from ([0-9.]+)");

  private static final Pattern MAX_AUTH =
      Pattern.compile("maximum authentication attempts exceeded for (?:invalid user )?(\\S+) from ([0-9.]+)");

  private static final Pattern SUDO_COMMAND =
      Pattern.compile("sudo:\\s+(\\S+)\\s+:.*COMMAND=(.*)");

  public static void main(String[] args) throws Exception
  {
    // Le fichier auth.log doit être dans le dossier du projet
    ReadLines reader = new ReadLines(new FileInputStream("auth.log"));
    Pullable p = reader.getPullableOutput();

    System.out.println("=== Analyse SIEM avec BeepBeep sur auth.log ===");

    while (p.hasNext())
    {
      String line = (String) p.pull();

      // Affichage brut si tu veux voir le flux
      // System.out.println(line);

      detectSuccessfulLogin(line);
      detectInvalidUser(line);
      detectBruteForce(line);
      detectSuspiciousSudo(line);
    }

    System.out.println("=== Fin de l'analyse ===");
  }

  /**
   * Détection d'une connexion réussie SSH
   */
  private static void detectSuccessfulLogin(String line)
  {
    Matcher m = ACCEPTED_PUBLICKEY.matcher(line);
    if (m.find())
    {
      String user = m.group(1);
      String ip = m.group(2);

      lastSuccessfulUserByIp.put(ip, user);

      System.out.println("[INFO] Connexion réussie : user=" + user + " ip=" + ip);
    }
  }

  /**
   * Détection d'utilisateurs invalides
   */
  private static void detectInvalidUser(String line)
  {
    Matcher m = INVALID_USER.matcher(line);
    if (m.find())
    {
      String user = m.group(1);
      String ip = m.group(2);

      int count = invalidUserCounter.getOrDefault(ip, 0) + 1;
      invalidUserCounter.put(ip, count);

      System.out.println("[WARN] Tentative sur utilisateur invalide : user=" + user
          + " ip=" + ip + " count=" + count);

      if (count >= 2)
      {
        System.out.println("[ALERTE] Scan d'utilisateurs probable depuis ip=" + ip);
      }
    }
  }

  /**
   * Détection brute force / trop d'échecs d'authentification
   */
  private static void detectBruteForce(String line)
  {
    Matcher m = MAX_AUTH.matcher(line);
    if (m.find())
    {
      String user = m.group(1);
      String ip = m.group(2);

      int count = bruteForceCounter.getOrDefault(ip, 0) + 1;
      bruteForceCounter.put(ip, count);

      System.out.println("[WARN] Echecs SSH multiples : user=" + user
          + " ip=" + ip + " count=" + count);

      if (count >= 3)
      {
        System.out.println("[ALERTE CRITIQUE] Brute force SSH probable depuis ip=" + ip);
      }
    }
  }

  /**
   * Détection commandes sudo sensibles
   */
  private static void detectSuspiciousSudo(String line)
  {
    Matcher m = SUDO_COMMAND.matcher(line);
    if (m.find())
    {
      String user = m.group(1);
      String command = m.group(2).trim();

      if (isSensitiveCommand(command))
      {
        System.out.println("[ALERTE] Commande sudo sensible détectée : user="
            + user + " cmd=" + command);
      }
      else
      {
        System.out.println("[INFO] Commande sudo : user=" + user + " cmd=" + command);
      }
    }
  }

  /**
   * Liste simple de commandes sensibles
   */
  private static boolean isSensitiveCommand(String cmd)
  {
    String c = cmd.toLowerCase();

    return c.contains("curl")
        || c.contains("wget")
        || c.contains("nc ")
        || c.contains("/bin/su")
        || c.contains("service filebeat")
        || c.contains("apt-get install")
        || c.contains("dpkg -i");
  }
}