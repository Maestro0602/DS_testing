package com.itc.studentmgmt.model;

import java.sql.Date;

/**
 * Student entity class representing a student record
 * Contains student information including ID, name, email, and major
 */
public class Student {
    private String studentId;
    private String name;
    private String email;
    private String major;
    private String phone;
    private String address;
    private Date dateOfBirth;
    private Date enrollmentDate;
    private double gpa;
    private String status;
    
    /**
     * Constructor to create a new Student object
     */
    public Student(String studentId, String name, String email, String major) {
        this.studentId = studentId;
        this.name = name;
        this.email = email;
        this.major = major;
        this.status = "ACTIVE";
        this.gpa = 0.0;
    }
    
    // Getters
    public String getStudentId() { return studentId; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public String getMajor() { return major; }
    public String getPhone() { return phone; }
    public String getAddress() { return address; }
    public Date getDateOfBirth() { return dateOfBirth; }
    public Date getEnrollmentDate() { return enrollmentDate; }
    public double getGpa() { return gpa; }
    public String getStatus() { return status; }
    
    // Setters
    public void setName(String name) { this.name = name; }
    public void setEmail(String email) { this.email = email; }
    public void setMajor(String major) { this.major = major; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setAddress(String address) { this.address = address; }
    public void setDateOfBirth(Date dateOfBirth) { this.dateOfBirth = dateOfBirth; }
    public void setEnrollmentDate(Date enrollmentDate) { this.enrollmentDate = enrollmentDate; }
    public void setGpa(double gpa) { this.gpa = gpa; }
    public void setStatus(String status) { this.status = status; }
    
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