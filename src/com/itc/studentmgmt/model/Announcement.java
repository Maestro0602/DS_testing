package com.itc.studentmgmt.model;

import java.sql.Timestamp;

/**
 * Announcement model for system-wide announcements
 */
public class Announcement {
    private int id;
    private String title;
    private String content;
    private String createdBy;
    private Timestamp createdAt;
    private String targetRole; // "ALL", "STUDENT", "TEACHER"
    
    public Announcement() {}
    
    public Announcement(int id, String title, String content, String createdBy, 
                       Timestamp createdAt, String targetRole) {
        this.id = id;
        this.title = title;
        this.content = content;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
        this.targetRole = targetRole;
    }
    
    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public Timestamp getCreatedAt() { return createdAt; }
    public void setCreatedAt(Timestamp createdAt) { this.createdAt = createdAt; }
    
    public String getTargetRole() { return targetRole; }
    public void setTargetRole(String targetRole) { this.targetRole = targetRole; }
}
