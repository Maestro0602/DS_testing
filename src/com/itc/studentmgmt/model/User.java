package com.itc.studentmgmt.model;

/**
 * User model representing an authenticated user in the system.
 * 
 * @author Security Team
 * @version 3.0.0
 */
public class User {
    private String username;
    private String passwordHash;
    private UserRole role;
    private String sessionToken;
    
    /**
     * Default constructor for creating empty User objects.
     */
    public User() {
        // Default constructor
    }
    
    /**
     * Constructor with all required fields.
     */
    public User(String username, String passwordHash, UserRole role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
    }
    
    // Getters
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public UserRole getRole() { return role; }
    public String getSessionToken() { return sessionToken; }
    
    // Setters
    public void setUsername(String username) {
        this.username = username;
    }
    
    public void setPasswordHash(String passwordHash) { 
        this.passwordHash = passwordHash; 
    }
    
    public void setRole(UserRole role) {
        this.role = role;
    }
    
    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }
    
    @Override
    public String toString() {
        return "User{username='" + username + "', role=" + role + "}";
    }
}