// AuthenticationService.java
import java.io.*;
import java.sql.*;
import javax.naming.*;
import javax.naming.directory.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.servlet.http.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.*;

public class AuthenticationService {
    private static final String SECRET_KEY = "MySecretKey123";
    private Map<String, UserSession> sessionCache = new HashMap<>();
    
    // Vulnerabilidad 1: SQL Injection de segundo orden
    public boolean authenticateUser(String username, String password) {
        try {
            Connection conn = getConnection();
            
            // Primera query "segura" con prepared statement
            PreparedStatement stmt = conn.prepareStatement(
                "SELECT user_id, password_hash FROM users WHERE username = ?"
            );
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                String userId = rs.getString("user_id");
                String storedHash = rs.getString("password_hash");
                
                if (verifyPassword(password, storedHash)) {
                    // Segunda query vulnerable usando el userId de la DB
                    // Si userId fue manipulado en la DB, SQL injection
                    String query = "UPDATE users SET last_login = NOW() WHERE user_id = " + userId;
                    conn.createStatement().execute(query);
                    return true;
                }
            }
        } catch (SQLException e) {
            logError(e);
        }
        return false;
    }
    
    // Vulnerabilidad 2: LDAP Injection con bypass de filtros
    public List<String> searchUsers(String searchTerm) {
        try {
            // Filtrado incompleto
            searchTerm = searchTerm.replace("*", "")
                                  .replace("(", "")
                                  .replace(")", "");
            
            // No filtra \00, \0a, etc. que pueden causar LDAP injection
            String filter = "(&(objectClass=user)(cn=*" + searchTerm + "*))";
            
            DirContext ctx = new InitialDirContext(env);
            NamingEnumeration results = ctx.search("dc=example,dc=com", filter, null);
            
            List<String> users = new ArrayList<>();
            while (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                users.add(sr.getName());
            }
            return users;
        } catch (NamingException e) {
            return Collections.emptyList();
        }
    }
    
    // Vulnerabilidad 3: Deserialización insegura con gadget chain
    public UserSession restoreSession(String sessionData) {
        try {
            byte[] data = Base64.getDecoder().decode(sessionData);
            
            // Verificación de firma insuficiente
            if (data.length > 32) {
                byte[] signature = Arrays.copyOfRange(data, 0, 32);
                byte[] payload = Arrays.copyOfRange(data, 32, data.length);
                
                // Verifica firma pero deserializa de todos modos
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(SECRET_KEY.getBytes());
                md.update(payload);
                byte[] expectedSig = md.digest();
                
                // Deserialización ocurre antes de validación compl
