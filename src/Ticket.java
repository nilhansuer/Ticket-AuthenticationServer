
public class Ticket {
    private String username;
    private String sessionKey_C_TGS;
    private long expirationTime;

    public Ticket(String username, String sessionKey_C_TGS, long expirationTime) {
        this.username = username;
        this.sessionKey_C_TGS = sessionKey_C_TGS;
        this.expirationTime = expirationTime;
    }

    public String getUsername() {
        return username;
    }
    
    public String getSessionKey_C_TGS() {
    	return sessionKey_C_TGS;
    }

    public long getExpirationTime() {
        return expirationTime;
    }
}