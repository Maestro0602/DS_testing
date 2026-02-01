package com.itc.studentmgmt.model;

import java.sql.Time;

/**
 * Schedule model for class schedules
 */
public class Schedule {
    private int id;
    private String courseCode;
    private String courseName;
    private String teacherUsername;
    private String dayOfWeek; // MONDAY, TUESDAY, etc.
    private Time startTime;
    private Time endTime;
    private String room;
    private String semester;
    
    public Schedule() {}
    
    public Schedule(int id, String courseCode, String courseName, String teacherUsername,
                   String dayOfWeek, Time startTime, Time endTime, String room, String semester) {
        this.id = id;
        this.courseCode = courseCode;
        this.courseName = courseName;
        this.teacherUsername = teacherUsername;
        this.dayOfWeek = dayOfWeek;
        this.startTime = startTime;
        this.endTime = endTime;
        this.room = room;
        this.semester = semester;
    }
    
    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getCourseCode() { return courseCode; }
    public void setCourseCode(String courseCode) { this.courseCode = courseCode; }
    
    public String getCourseName() { return courseName; }
    public void setCourseName(String courseName) { this.courseName = courseName; }
    
    public String getTeacherUsername() { return teacherUsername; }
    public void setTeacherUsername(String teacherUsername) { this.teacherUsername = teacherUsername; }
    
    public String getDayOfWeek() { return dayOfWeek; }
    public void setDayOfWeek(String dayOfWeek) { this.dayOfWeek = dayOfWeek; }
    
    public Time getStartTime() { return startTime; }
    public void setStartTime(Time startTime) { this.startTime = startTime; }
    
    public Time getEndTime() { return endTime; }
    public void setEndTime(Time endTime) { this.endTime = endTime; }
    
    public String getRoom() { return room; }
    public void setRoom(String room) { this.room = room; }
    
    public String getSemester() { return semester; }
    public void setSemester(String semester) { this.semester = semester; }
}
