package com.itc.studentmgmt.ui;

import com.itc.studentmgmt.model.*;
import com.itc.studentmgmt.dao.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * 📚 TEACHER PANEL
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Panel for teachers to manage:
 * - Class schedules
 * - Announcements
 * - View enrolled students
 * 
 * @author Security Team
 * @version 1.0.0
 */
public class TeacherPanel extends JPanel {
    
    private User currentUser;
    private ScheduleDAO scheduleDAO;
    private AnnouncementDAO announcementDAO;
    private StudentEnrollmentDAO enrollmentDAO;
    
    // Tables
    private JTable scheduleTable;
    private DefaultTableModel scheduleTableModel;
    private JTable announcementTable;
    private DefaultTableModel announcementTableModel;
    
    // Modern color scheme
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color SECONDARY_COLOR = new Color(52, 152, 219);
    private static final Color BACKGROUND_COLOR = new Color(236, 240, 241);
    private static final Color CARD_COLOR = Color.WHITE;
    private static final Color TEXT_COLOR = new Color(44, 62, 80);
    private static final Color TABLE_HEADER = new Color(52, 73, 94);
    
    public TeacherPanel(User user) {
        this.currentUser = user;
        this.scheduleDAO = new ScheduleDAO();
        this.announcementDAO = new AnnouncementDAO();
        this.enrollmentDAO = new StudentEnrollmentDAO();
        initComponents();
        loadData();
    }
    
    private void initComponents() {
        setLayout(new BorderLayout());
        setBackground(BACKGROUND_COLOR);
        setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // Create tabbed pane for different sections
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Segoe UI", Font.BOLD, 13));
        tabbedPane.setBackground(CARD_COLOR);
        
        // Add tabs
        tabbedPane.addTab("📅 My Schedules", createSchedulePanel());
        tabbedPane.addTab("📢 Announcements", createAnnouncementPanel());
        tabbedPane.addTab("👥 My Students", createStudentsPanel());
        
        add(tabbedPane, BorderLayout.CENTER);
    }
    
    private JPanel createSchedulePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // Header with title and buttons
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(CARD_COLOR);
        
        JLabel titleLabel = new JLabel("📅 Class Schedules");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(TEXT_COLOR);
        headerPanel.add(titleLabel, BorderLayout.WEST);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(CARD_COLOR);
        
        JButton addScheduleBtn = createStyledButton("➕ Add Schedule", true);
        addScheduleBtn.addActionListener(e -> showAddScheduleDialog());
        buttonPanel.add(addScheduleBtn);
        
        JButton refreshBtn = createStyledButton("🔄 Refresh", false);
        refreshBtn.addActionListener(e -> loadSchedules());
        buttonPanel.add(refreshBtn);
        
        headerPanel.add(buttonPanel, BorderLayout.EAST);
        panel.add(headerPanel, BorderLayout.NORTH);
        
        // Schedule table
        String[] columns = {"ID", "Course Code", "Course Name", "Day", "Start Time", "End Time", "Room", "Semester"};
        scheduleTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        scheduleTable = createStyledTable(scheduleTableModel);
        JScrollPane scrollPane = new JScrollPane(scheduleTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Action buttons at bottom
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        actionPanel.setBackground(CARD_COLOR);
        
        JButton editBtn = createStyledButton("✏️ Edit", true);
        editBtn.addActionListener(e -> editSelectedSchedule());
        actionPanel.add(editBtn);
        
        JButton deleteBtn = createStyledButton("🗑️ Delete", false);
        deleteBtn.setBackground(new Color(231, 76, 60));
        deleteBtn.addActionListener(e -> deleteSelectedSchedule());
        actionPanel.add(deleteBtn);
        
        panel.add(actionPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createAnnouncementPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(CARD_COLOR);
        
        JLabel titleLabel = new JLabel("📢 Announcements");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(TEXT_COLOR);
        headerPanel.add(titleLabel, BorderLayout.WEST);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(CARD_COLOR);
        
        JButton addAnnouncementBtn = createStyledButton("➕ New Announcement", true);
        addAnnouncementBtn.addActionListener(e -> showAddAnnouncementDialog());
        buttonPanel.add(addAnnouncementBtn);
        
        headerPanel.add(buttonPanel, BorderLayout.EAST);
        panel.add(headerPanel, BorderLayout.NORTH);
        
        // Announcement table
        String[] columns = {"ID", "Title", "Target Audience", "Created At"};
        announcementTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        announcementTable = createStyledTable(announcementTableModel);
        JScrollPane scrollPane = new JScrollPane(announcementTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Action buttons
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        actionPanel.setBackground(CARD_COLOR);
        
        JButton viewBtn = createStyledButton("👁️ View Details", true);
        viewBtn.addActionListener(e -> viewSelectedAnnouncement());
        actionPanel.add(viewBtn);
        
        JButton deleteBtn = createStyledButton("🗑️ Delete", false);
        deleteBtn.setBackground(new Color(231, 76, 60));
        deleteBtn.addActionListener(e -> deleteSelectedAnnouncement());
        actionPanel.add(deleteBtn);
        
        panel.add(actionPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createStudentsPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(CARD_COLOR);
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // Header
        JLabel titleLabel = new JLabel("👥 Students Enrolled in My Classes");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(TEXT_COLOR);
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Info panel
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBackground(new Color(232, 245, 233));
        infoPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        JLabel infoLabel = new JLabel("📊 View students enrolled in your courses");
        infoLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        infoPanel.add(infoLabel);
        
        // Get schedules for this teacher and show enrolled students
        List<Schedule> mySchedules = scheduleDAO.getSchedulesByTeacher(currentUser.getUsername());
        
        if (mySchedules.isEmpty()) {
            JLabel noSchedule = new JLabel("You have no classes scheduled yet.");
            noSchedule.setFont(new Font("Segoe UI", Font.ITALIC, 13));
            noSchedule.setForeground(new Color(127, 140, 141));
            infoPanel.add(Box.createVerticalStrut(10));
            infoPanel.add(noSchedule);
        } else {
            infoPanel.add(Box.createVerticalStrut(10));
            JLabel countLabel = new JLabel("📚 You are teaching " + mySchedules.size() + " course(s)");
            countLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
            infoPanel.add(countLabel);
            
            for (Schedule s : mySchedules) {
                infoPanel.add(Box.createVerticalStrut(5));
                JLabel courseLabel = new JLabel("   • " + s.getCourseCode() + " - " + s.getCourseName() + 
                    " (" + s.getDayOfWeek() + " " + s.getStartTime() + "-" + s.getEndTime() + ")");
                courseLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                infoPanel.add(courseLabel);
            }
        }
        
        panel.add(infoPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JTable createStyledTable(DefaultTableModel model) {
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(35);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        table.setSelectionBackground(new Color(52, 152, 219, 50));
        table.setShowVerticalLines(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        
        JTableHeader header = table.getTableHeader();
        header.setBackground(TABLE_HEADER);
        header.setForeground(Color.WHITE);
        header.setFont(new Font("Segoe UI", Font.BOLD, 12));
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 40));
        
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
        
        return table;
    }
    
    private JButton createStyledButton(String text, boolean primary) {
        JButton button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.BOLD, 12));
        button.setForeground(Color.WHITE);
        button.setBackground(primary ? PRIMARY_COLOR : new Color(149, 165, 166));
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setBorder(new EmptyBorder(10, 20, 10, 20));
        return button;
    }
    
    private void loadData() {
        loadSchedules();
        loadAnnouncements();
    }
    
    private void loadSchedules() {
        scheduleTableModel.setRowCount(0);
        List<Schedule> schedules = scheduleDAO.getSchedulesByTeacher(currentUser.getUsername());
        
        for (Schedule s : schedules) {
            scheduleTableModel.addRow(new Object[]{
                s.getId(),
                s.getCourseCode(),
                s.getCourseName(),
                s.getDayOfWeek(),
                s.getStartTime(),
                s.getEndTime(),
                s.getRoom(),
                s.getSemester()
            });
        }
    }
    
    private void loadAnnouncements() {
        announcementTableModel.setRowCount(0);
        // Get announcements created by this teacher
        List<Announcement> announcements = announcementDAO.getAnnouncementsForRole("TEACHER");
        
        for (Announcement a : announcements) {
            if (a.getCreatedBy().equals(currentUser.getUsername())) {
                announcementTableModel.addRow(new Object[]{
                    a.getId(),
                    a.getTitle(),
                    a.getTargetRole(),
                    a.getCreatedAt()
                });
            }
        }
    }
    
    private void showAddScheduleDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Add New Schedule", true);
        dialog.setSize(450, 450);
        dialog.setLocationRelativeTo(this);
        
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(new EmptyBorder(20, 30, 20, 30));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);
        
        JTextField courseCodeField = createTextField();
        JTextField courseNameField = createTextField();
        String[] days = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
        JComboBox<String> dayCombo = new JComboBox<>(days);
        JTextField startTimeField = createTextField();
        startTimeField.setText("09:00");
        JTextField endTimeField = createTextField();
        endTimeField.setText("10:30");
        JTextField roomField = createTextField();
        JTextField semesterField = createTextField();
        semesterField.setText("2024-2025 Semester 1");
        
        addField(panel, gbc, 0, "Course Code:", courseCodeField);
        addField(panel, gbc, 1, "Course Name:", courseNameField);
        
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(new JLabel("Day of Week:"), gbc);
        gbc.gridx = 1;
        panel.add(dayCombo, gbc);
        
        addField(panel, gbc, 3, "Start Time (HH:MM):", startTimeField);
        addField(panel, gbc, 4, "End Time (HH:MM):", endTimeField);
        addField(panel, gbc, 5, "Room:", roomField);
        addField(panel, gbc, 6, "Semester:", semesterField);
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        btnPanel.setBackground(Color.WHITE);
        
        JButton saveBtn = createStyledButton("Save", true);
        saveBtn.addActionListener(e -> {
            Schedule schedule = new Schedule();
            schedule.setCourseCode(courseCodeField.getText().trim());
            schedule.setCourseName(courseNameField.getText().trim());
            schedule.setTeacherUsername(currentUser.getUsername());
            schedule.setDayOfWeek((String) dayCombo.getSelectedItem());
            schedule.setStartTime(startTimeField.getText().trim());
            schedule.setEndTime(endTimeField.getText().trim());
            schedule.setRoom(roomField.getText().trim());
            schedule.setSemester(semesterField.getText().trim());
            
            if (scheduleDAO.addSchedule(schedule)) {
                JOptionPane.showMessageDialog(dialog, "Schedule added successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadSchedules();
                dialog.dispose();
            } else {
                JOptionPane.showMessageDialog(dialog, "Failed to add schedule", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton cancelBtn = createStyledButton("Cancel", false);
        cancelBtn.addActionListener(e -> dialog.dispose());
        
        btnPanel.add(saveBtn);
        btnPanel.add(cancelBtn);
        
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 8, 8, 8);
        panel.add(btnPanel, gbc);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void showAddAnnouncementDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Create Announcement", true);
        dialog.setSize(500, 400);
        dialog.setLocationRelativeTo(this);
        
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(Color.WHITE);
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(Color.WHITE);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);
        
        JTextField titleField = createTextField();
        String[] targets = {"ALL", "STUDENT", "TEACHER"};
        JComboBox<String> targetCombo = new JComboBox<>(targets);
        JTextArea contentArea = new JTextArea(6, 30);
        contentArea.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199)),
            new EmptyBorder(8, 8, 8, 8)
        ));
        
        addField(formPanel, gbc, 0, "Title:", titleField);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        formPanel.add(new JLabel("Target Audience:"), gbc);
        gbc.gridx = 1;
        formPanel.add(targetCombo, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        formPanel.add(new JLabel("Content:"), gbc);
        
        gbc.gridy = 3;
        JScrollPane scroll = new JScrollPane(contentArea);
        formPanel.add(scroll, gbc);
        
        panel.add(formPanel, BorderLayout.CENTER);
        
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        btnPanel.setBackground(Color.WHITE);
        
        JButton postBtn = createStyledButton("📢 Post Announcement", true);
        postBtn.addActionListener(e -> {
            if (titleField.getText().trim().isEmpty() || contentArea.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Title and content are required", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            Announcement announcement = new Announcement();
            announcement.setTitle(titleField.getText().trim());
            announcement.setContent(contentArea.getText().trim());
            announcement.setCreatedBy(currentUser.getUsername());
            
            String target = (String) targetCombo.getSelectedItem();
            announcement.setTargetRole(target);
            
            if (announcementDAO.addAnnouncement(announcement)) {
                JOptionPane.showMessageDialog(dialog, "Announcement posted!", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadAnnouncements();
                dialog.dispose();
            } else {
                JOptionPane.showMessageDialog(dialog, "Failed to post announcement", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton cancelBtn = createStyledButton("Cancel", false);
        cancelBtn.addActionListener(e -> dialog.dispose());
        
        btnPanel.add(postBtn);
        btnPanel.add(cancelBtn);
        panel.add(btnPanel, BorderLayout.SOUTH);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void editSelectedSchedule() {
        int row = scheduleTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Please select a schedule to edit", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        // TODO: Implement edit dialog
        JOptionPane.showMessageDialog(this, "Edit schedule feature coming soon!", "Info", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void deleteSelectedSchedule() {
        int row = scheduleTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Please select a schedule to delete", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int scheduleId = (int) scheduleTableModel.getValueAt(row, 0);
        int confirm = JOptionPane.showConfirmDialog(this, 
            "Are you sure you want to delete this schedule?", 
            "Confirm Delete", 
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (scheduleDAO.deleteSchedule(scheduleId)) {
                JOptionPane.showMessageDialog(this, "Schedule deleted", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadSchedules();
            } else {
                JOptionPane.showMessageDialog(this, "Failed to delete schedule", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void viewSelectedAnnouncement() {
        int row = announcementTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Please select an announcement to view", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int announcementId = (int) announcementTableModel.getValueAt(row, 0);
        String title = (String) announcementTableModel.getValueAt(row, 1);
        
        // TODO: Show announcement details dialog
        JOptionPane.showMessageDialog(this, 
            "Announcement ID: " + announcementId + "\nTitle: " + title, 
            "Announcement Details", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void deleteSelectedAnnouncement() {
        int row = announcementTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Please select an announcement to delete", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int announcementId = (int) announcementTableModel.getValueAt(row, 0);
        int confirm = JOptionPane.showConfirmDialog(this, 
            "Are you sure you want to delete this announcement?", 
            "Confirm Delete", 
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (announcementDAO.deleteAnnouncement(announcementId)) {
                JOptionPane.showMessageDialog(this, "Announcement deleted", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadAnnouncements();
            } else {
                JOptionPane.showMessageDialog(this, "Failed to delete announcement", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private JTextField createTextField() {
        JTextField field = new JTextField(20);
        field.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199)),
            new EmptyBorder(8, 12, 8, 12)
        ));
        return field;
    }
    
    private void addField(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        JLabel lbl = new JLabel(label);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 13));
        panel.add(lbl, gbc);
        
        gbc.gridx = 1;
        panel.add(field, gbc);
    }
}
