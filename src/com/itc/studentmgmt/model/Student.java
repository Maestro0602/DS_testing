package com.itc.studentmgmt.model;

/**
 * Student entity class representing a student record
 * Contains student information including ID, name, email, and major
 */
public class Student {
    private String studentId;
    private String name;
    private String email;
    private String major;
    
    /**
     * Constructor to create a new Student object
     * @param studentId Unique identifier for the student
     * @param name Full name of the student
     * @param email Email address of the student
     * @param major Academic major/program of the student
     */
    public Student(String studentId, String name, String email, String major) {
        this.studentId = studentId;
        this.name = name;
        this.email = email;
        this.major = major;
    }
    
    // Getters
    public String getStudentId() { 
        return studentId; 
    }
    
    public String getName() { 
        return name; 
    }
    
    public String getEmail() { 
        return email; 
    }
    
    public String getMajor() { 
        return major; 
    }
    
    // Setters
    public void setName(String name) { 
        this.name = name; 
    }
    
    public void setEmail(String email) { 
        this.email = email; 
    }
    
    public void setMajor(String major) { 
        this.major = major; 
    }
    
    @Override
    public String toString() {
        return "Student{" +
                "studentId='" + studentId + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", major='" + major + '\'' +
                '}';
    }
}