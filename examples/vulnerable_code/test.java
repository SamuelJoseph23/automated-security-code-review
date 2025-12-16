import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import java.io.File;

public class VulnerableApp {

    // VULNERABLE: Hardcoded Credentials (CRITICAL)
    private static final String DB_URL = "jdbc:mysql://localhost/test";
    private static final String USER = "admin";
    private static final String PASS = "super_secret_password_123";
    private static final String AWS_KEY = "AKIAiosFODNN7EXAMPLE";

    public void getUserData(String username) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: SQL Injection (CRITICAL)
            // String concatenation allows ' OR '1'='1 attacks
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println("User: " + rs.getString("name"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void runSystemCommand(String userInput) {
        try {
            // VULNERABLE: Command Injection (CRITICAL)
            // User input is passed directly to the shell
            Runtime.getRuntime().exec("ping " + userInput);
            
            // Another variant
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "dir " + userInput);
            pb.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void weakCrypto() {
        try {
            // VULNERABLE: Weak Cryptography (HIGH)
            // MD5 is broken and should not be used
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest("password".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String displayProfile(String bio) {
        // VULNERABLE: Cross-Site Scripting (XSS) (HIGH)
        // Returning raw HTML input without sanitization
        return "<div>User Bio: " + bio + "</div>";
    }
}
