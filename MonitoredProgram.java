import java.io.FileWriter;

public class MonitoredProgram {
    public static void main(String[] args) throws Exception {
        FileWriter fw = new FileWriter("test.txt");
        fw.write("Hello World");
        fw.write("More data");
        fw.close();
    }
}
