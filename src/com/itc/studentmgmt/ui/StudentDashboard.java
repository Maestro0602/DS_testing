package com.itc.studentmgmt.ui;

import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.Announcement;
import com.itc.studentmgmt.model.Schedule;
import com.itc.studentmgmt.dao.AnnouncementDAO;
import com.itc.studentmgmt.dao.ScheduleDAO;
import com.itc.studentmgmt.dao.StudentDAO;
import com.itc.studentmgmt.model.Student;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.List;

/**
 * Student Dashboard - Shows schedule, announcements, and student info
 */
public class StudentDashboard extends JPanel {
    private User currentUser;
    private AnnouncementDAO announcementDAO;
    private ScheduleDAO scheduleDAO;
    private StudentDAO studentDAO;
    
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color SECONDARY_COLOR = new Color(52, 152, 219);
    private static final Color BACKGROUND_COLOR = new Color(236, 240, 241);
    private static final Color CARD_COLOR = Color.WHITE;
    private static final Color TEXT_COLOR = new Color(44, 62, 80);
    private static final Color LIGHT_TEXT = new Color(127, 140, 141);
    
    public StudentDashboard(User user) {
        this.currentUser = user;
        this.announcementDAO = new AnnouncementDAO();
        this.scheduleDAO = new ScheduleDAO();
        this.studentDAO = new StudentDAO();
        
        setLayout(new BorderLayout(15, 15));
        setBackground(BACKGROUND_COLOR);
        setBorder(new EmptyBorder(20, 20, 20, 20));
        
        initComponents();
    }
    
    private void initComponents() {
        // Main content panel
        JPanel contentPanel = new JPanel(new BorderLayout(15, 15));
        contentPanel.setOpaque(false);
        
        // Top section - Welcome and Quick Info
        JPanel topPanel = createWelcomePanel();
        contentPanel.add(topPanel, BorderLayout.NORTH);
        
        // Center section - Two columns
        JPanel centerPanel = new JPanel(new GridLayout(1, 2, 15, 0));
        centerPanel.setOpaque(false);
        
        // Left column - Schedule
        JPanel schedulePanel = createSchedulePanel();
        centerPanel.add(schedulePanel);
        
        // Right column - Announcements
        JPanel announcementsPanel = createAnnouncementsPanel();
        centerPanel.add(announcementsPanel);
        
        contentPanel.add(centerPanel, BorderLayout.CENTER);
        
        add(contentPanel, BorderLayout.CENTER);
    }
    
    private JPanel createWelcomePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout(15, 0));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1, true),
            new EmptyBorder(20, 25, 20, 25)
        ));
        
        // Left side - Welcome message
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setOpaque(false);
        
        JLabel welcomeLabel = new JLabel("Welcome Back, " + currentUser.getUsername() + "!");
        welcomeLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        welcomeLabel.setForeground(TEXT_COLOR);
        leftPanel.add(welcomeLabel);
        
        leftPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        
        JLabel roleLabel = new JLabel("🎓 Student Dashboard");
        roleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        roleLabel.setForeground(LIGHT_TEXT);
        leftPanel.add(roleLabel);
        
        panel.add(leftPanel, BorderLayout.WEST);
        
        // Right side - Quick stats
        JPanel statsPanel = new JPanel(new GridLayout(1, 3, 15, 0));
        statsPanel.setOpaque(false);
        
        // Get student info
        Student student = studentDAO.getStudentByUsername(currentUser.getUsername());
        int enrolledCourses = scheduleDAO.getSchedulesByStudent(
            student != null ? student.getStudentId() : "").size();
        
        statsPanel.add(createStatCard("📚 Enrolled Courses", String.valueOf(enrolledCourses), PRIMARY_COLOR));
        statsPanel.add(createStatCard("📊 GPA", 
            student != null ? String.format("%.2f", student.getGpa()) : "0.00", 
            new Color(46, 204, 113)));
        statsPanel.add(createStatCard("📅 Semester", "2026-1", new Color(155, 89, 182)));
        
        panel.add(statsPanel, BorderLayout.EAST);
        
        return panel;
    }
    
    private JPanel createStatCard(String title, String value, Color color) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(new Color(color.getRed(), color.getGreen(), color.getBlue(), 20));
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 1, true),
            new EmptyBorder(10, 15, 10, 15)
        ));
        
        JLabel valueLabel = new JLabel(value);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        valueLabel.setForeground(color);
        valueLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(valueLabel);
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(titleLabel);
        
        return card;
    }
    
    private JPanel createSchedulePanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1, true),
            new EmptyBorder(20, 20, 20, 20)
        ));
        
        // Header
        JLabel headerLabel = new JLabel("📅 My Class Schedule");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        headerLabel.setForeground(TEXT_COLOR);
        panel.add(headerLabel, BorderLayout.NORTH);
        
        // Schedule list
        JPanel scheduleList = new JPanel();
        scheduleList.setLayout(new BoxLayout(scheduleList, BoxLayout.Y_AXIS));
        scheduleList.setOpaque(false);
        
        // Get student schedule
        Student student = studentDAO.getStudentByUsername(currentUser.getUsername());
        if (student != null) {
            List<Schedule> schedules = scheduleDAO.getSchedulesByStudent(student.getStudentId());
            
            if (schedules.isEmpty()) {
                JLabel noScheduleLabel = new JLabel("No classes enrolled yet");
                noScheduleLabel.setFont(new Font("Segoe UI", Font.ITALIC, 14));
                noScheduleLabel.setForeground(LIGHT_TEXT);
                scheduleList.add(noScheduleLabel);
            } else {
                String currentDay = "";
                for (Schedule schedule : schedules) {
                    if (!schedule.getDayOfWeek().equals(currentDay)) {
                        currentDay = schedule.getDayOfWeek();
                        JLabel dayLabel = new JLabel(currentDay);
                        dayLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
                        dayLabel.setForeground(PRIMARY_COLOR);
                        dayLabel.setBorder(new EmptyBorder(10, 0, 5, 0));
                        scheduleList.add(dayLabel);
                    }
                    scheduleList.add(createScheduleItem(schedule));
                }
            }
        }
        
        JScrollPane scrollPane = new JScrollPane(scheduleList);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createScheduleItem(Schedule schedule) {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(new Color(245, 247, 250));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1, true),
            new EmptyBorder(10, 15, 10, 15)
        ));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
        
        // Time
        JPanel timePanel = new JPanel();
        timePanel.setLayout(new BoxLayout(timePanel, BoxLayout.Y_AXIS));
        timePanel.setOpaque(false);
        
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm");
        JLabel timeLabel = new JLabel(timeFormat.format(schedule.getStartTime()));
        timeLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        timeLabel.setForeground(PRIMARY_COLOR);
        timePanel.add(timeLabel);
        
        JLabel endTimeLabel = new JLabel(timeFormat.format(schedule.getEndTime()));
        endTimeLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        endTimeLabel.setForeground(LIGHT_TEXT);
        timePanel.add(endTimeLabel);
        
        panel.add(timePanel, BorderLayout.WEST);
        
        // Course info
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setOpaque(false);
        
        JLabel courseLabel = new JLabel(schedule.getCourseName());
        courseLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        courseLabel.setForeground(TEXT_COLOR);
        infoPanel.add(courseLabel);
        
        JLabel detailsLabel = new JLabel(schedule.getCourseCode() + " • Room " + schedule.getRoom());
        detailsLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        detailsLabel.setForeground(LIGHT_TEXT);
        infoPanel.add(detailsLabel);
        
        panel.add(infoPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAnnouncementsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 15));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1, true),
            new EmptyBorder(20, 20, 20, 20)
        ));
        
        // Header
        JLabel headerLabel = new JLabel("📢 Announcements");
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        headerLabel.setForeground(TEXT_COLOR);
        panel.add(headerLabel, BorderLayout.NORTH);
        
        // Announcements list
        JPanel announcementsList = new JPanel();
        announcementsList.setLayout(new BoxLayout(announcementsList, BoxLayout.Y_AXIS));
        announcementsList.setOpaque(false);
        
        List<Announcement> announcements = announcementDAO.getAnnouncementsForRole("STUDENT");
        
        if (announcements.isEmpty()) {
            JLabel noAnnouncementsLabel = new JLabel("No announcements yet");
            noAnnouncementsLabel.setFont(new Font("Segoe UI", Font.ITALIC, 14));
            noAnnouncementsLabel.setForeground(LIGHT_TEXT);
            announcementsList.add(noAnnouncementsLabel);
        } else {
            for (Announcement announcement : announcements) {
                announcementsList.add(createAnnouncementItem(announcement));
                announcementsList.add(Box.createRigidArea(new Dimension(0, 10)));
            }
        }
        
        JScrollPane scrollPane = new JScrollPane(announcementsList);
        scrollPane.setBorder(null);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAnnouncementItem(Announcement announcement) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(new Color(245, 247, 250));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1, true),
            new EmptyBorder(15, 15, 15, 15)
        ));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Title
        JLabel titleLabel = new JLabel(announcement.getTitle());
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(titleLabel);
        
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        
        // Content
        JTextArea contentArea = new JTextArea(announcement.getContent());
        contentArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        contentArea.setForeground(TEXT_COLOR);
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setEditable(false);
        contentArea.setOpaque(false);
        contentArea.setBorder(null);
        panel.add(contentArea);
        
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        
        // Footer
        SimpleDateFormat dateFormat = new SimpleDateFormat("MMM dd, yyyy HH:mm");
        JLabel footerLabel = new JLabel("Posted by " + announcement.getCreatedBy() + 
            " • " + dateFormat.format(announcement.getCreatedAt()));
        footerLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        footerLabel.setForeground(LIGHT_TEXT);
        footerLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(footerLabel);
        
        return panel;
    }
    
    public void refresh() {
        removeAll();
        initComponents();
        revalidate();
        repaint();
    }
}
