package com.itc.studentmgmt.model;

/**
 * Student enrollment for linking students to schedules
 */
public class StudentEnrollment {
    private int id;
    private String studentId;
    private int scheduleId;
    private String grade;
    private String status; // "ENROLLED", "COMPLETED", "DROPPED"
    
    public StudentEnrollment() {}
    
    public StudentEnrollment(int id, String studentId, int scheduleId, String grade, String status) {
        this.id = id;
        this.studentId = studentId;
        this.scheduleId = scheduleId;
        this.grade = grade;
        this.status = status;
    }
    
    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getStudentId() { return studentId; }
    public void setStudentId(String studentId) { this.studentId = studentId; }
    
    public int getScheduleId() { return scheduleId; }
    public void setScheduleId(int scheduleId) { this.scheduleId = scheduleId; }
    
    public String getGrade() { return grade; }
    public void setGrade(String grade) { this.grade = grade; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
