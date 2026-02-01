package com.itc.studentmgmt.ui;

import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.UserRole;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Enhanced Main Frame with role-based dashboards
 */
public class EnhancedMainFrame extends JFrame {
    private User currentUser;
    private JPanel sidebarPanel;
    private JPanel contentPanel;
    private String currentView = "dashboard";
    
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color SECONDARY_COLOR = new Color(52, 152, 219);
    private static final Color BACKGROUND_COLOR = new Color(236, 240, 241);
    private static final Color SIDEBAR_COLOR = new Color(52, 73, 94);
    private static final Color TEXT_COLOR = new Color(44, 62, 80);
    private static final Color LIGHT_TEXT = new Color(127, 140, 141);
    
    public EnhancedMainFrame(User user) {
        this.currentUser = user;
        initComponents();
    }
    
    private void initComponents() {
        setTitle("Student Management System - ITC");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1400, 850);
        setLocationRelativeTo(null);
        
        // Main container
        JPanel mainContainer = new JPanel(new BorderLayout());
        mainContainer.setBackground(BACKGROUND_COLOR);
        
        // Sidebar
        sidebarPanel = createSidebar();
        mainContainer.add(sidebarPanel, BorderLayout.WEST);
        
        // Content area
        contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBackground(BACKGROUND_COLOR);
        mainContainer.add(contentPanel, BorderLayout.CENTER);
        
        // Load initial dashboard
        showDashboard();
        
        add(mainContainer);
    }
    
    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(SIDEBAR_COLOR);
        sidebar.setPreferredSize(new Dimension(250, getHeight()));
        sidebar.setBorder(new EmptyBorder(20, 0, 20, 0));
        
        // Logo/Title
        JPanel logoPanel = new JPanel();
        logoPanel.setLayout(new BoxLayout(logoPanel, BoxLayout.Y_AXIS));
        logoPanel.setOpaque(false);
        logoPanel.setBorder(new EmptyBorder(0, 20, 30, 20));
        
        JLabel iconLabel = new JLabel("🎓", SwingConstants.CENTER);
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 40));
        iconLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        logoPanel.add(iconLabel);
        
        JLabel titleLabel = new JLabel("ITC System", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        logoPanel.add(titleLabel);
        
        sidebar.add(logoPanel);
        
        // Navigation menu
        if (currentUser.getRole() == UserRole.STUDENT) {
            sidebar.add(createMenuItem("🏠 Dashboard", "dashboard"));
            sidebar.add(createMenuItem("📚 My Courses", "courses"));
            sidebar.add(createMenuItem("📊 Grades", "grades"));
            sidebar.add(createMenuItem("📅 Schedule", "schedule"));
            sidebar.add(createMenuItem("📢 Announcements", "announcements"));
        } else if (currentUser.getRole() == UserRole.TEACHER) {
            sidebar.add(createMenuItem("🏠 Dashboard", "dashboard"));
            sidebar.add(createMenuItem("👥 Students", "students"));
            sidebar.add(createMenuItem("📚 My Classes", "classes"));
            sidebar.add(createMenuItem("📊 Grades Management", "grades"));
            sidebar.add(createMenuItem("📅 Schedule", "schedule"));
            sidebar.add(createMenuItem("📢 Announcements", "announcements"));
        } else { // ADMIN
            sidebar.add(createMenuItem("🏠 Dashboard", "dashboard"));
            sidebar.add(createMenuItem("👥 Student Management", "students"));
            sidebar.add(createMenuItem("👨‍🏫 Teacher Management", "teachers"));
            sidebar.add(createMenuItem("📚 Course Management", "courses"));
            sidebar.add(createMenuItem("📅 Schedule Management", "schedule"));
            sidebar.add(createMenuItem("📢 Announcements", "announcements"));
            sidebar.add(createMenuItem("⚙️ System Settings", "settings"));
        }
        
        // Spacer
        sidebar.add(Box.createVerticalGlue());
        
        // User info at bottom
        JPanel userPanel = new JPanel();
        userPanel.setLayout(new BoxLayout(userPanel, BoxLayout.Y_AXIS));
        userPanel.setOpaque(false);
        userPanel.setBorder(new EmptyBorder(20, 20, 0, 20));
        
        JLabel usernameLabel = new JLabel(currentUser.getUsername());
        usernameLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        usernameLabel.setForeground(Color.WHITE);
        userPanel.add(usernameLabel);
        
        JLabel roleLabel = new JLabel(currentUser.getRole().toString());
        roleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        roleLabel.setForeground(new Color(255, 255, 255, 180));
        userPanel.add(roleLabel);
        
        sidebar.add(userPanel);
        
        sidebar.add(Box.createRigidArea(new Dimension(0, 15)));
        
        // Logout button
        JButton logoutButton = createSidebarButton("🚪 Logout");
        logoutButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to logout?",
                "Logout Confirmation",
                JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                dispose();
                new LoginFrame().setVisible(true);
            }
        });
        sidebar.add(logoutButton);
        
        return sidebar;
    }
    
    private JButton createMenuItem(String text, String view) {
        JButton button = createSidebarButton(text);
        button.addActionListener(e -> switchView(view));
        if (view.equals(currentView)) {
            button.setBackground(new Color(41, 128, 185));
        }
        return button;
    }
    
    private JButton createSidebarButton(String text) {
        JButton button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        button.setForeground(Color.WHITE);
        button.setBackground(SIDEBAR_COLOR);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setMaximumSize(new Dimension(Integer.MAX_VALUE, 45));
        button.setBorder(new EmptyBorder(10, 20, 10, 20));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                if (!button.getBackground().equals(PRIMARY_COLOR)) {
                    button.setBackground(new Color(44, 62, 80));
                }
            }
            
            public void mouseExited(java.awt.event.MouseEvent evt) {
                if (!button.getBackground().equals(PRIMARY_COLOR)) {
                    button.setBackground(SIDEBAR_COLOR);
                }
            }
        });
        
        return button;
    }
    
    private void switchView(String view) {
        currentView = view;
        contentPanel.removeAll();
        
        switch (view) {
            case "dashboard":
                showDashboard();
                break;
            case "students":
                showStudentsManagement();
                break;
            default:
                showComingSoon(view);
        }
        
        // Update sidebar buttons
        Component[] components = sidebarPanel.getComponents();
        for (Component comp : components) {
            if (comp instanceof JButton) {
                JButton btn = (JButton) comp;
                btn.setBackground(SIDEBAR_COLOR);
            }
        }
        
        contentPanel.revalidate();
        contentPanel.repaint();
    }
    
    private void showDashboard() {
        if (currentUser.getRole() == UserRole.STUDENT) {
            StudentDashboard dashboard = new StudentDashboard(currentUser);
            contentPanel.add(dashboard, BorderLayout.CENTER);
        } else {
            showComingSoon("dashboard for " + currentUser.getRole());
        }
    }
    
    private void showStudentsManagement() {
        // Reuse existing MainFrame student management
        MainFrame oldFrame = new MainFrame(currentUser);
        contentPanel.add(oldFrame.getContentPane(), BorderLayout.CENTER);
    }
    
    private void showComingSoon(String feature) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(BACKGROUND_COLOR);
        
        JPanel messagePanel = new JPanel();
        messagePanel.setLayout(new BoxLayout(messagePanel, BoxLayout.Y_AXIS));
        messagePanel.setOpaque(false);
        
        JLabel iconLabel = new JLabel("🚧", SwingConstants.CENTER);
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 60));
        iconLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        messagePanel.add(iconLabel);
        
        messagePanel.add(Box.createRigidArea(new Dimension(0, 20)));
        
        JLabel titleLabel = new JLabel("Coming Soon");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 28));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        messagePanel.add(titleLabel);
        
        messagePanel.add(Box.createRigidArea(new Dimension(0, 10)));
        
        JLabel messageLabel = new JLabel("The " + feature + " feature is under development");
        messageLabel.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        messageLabel.setForeground(LIGHT_TEXT);
        messageLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        messagePanel.add(messageLabel);
        
        panel.add(messagePanel);
        contentPanel.add(panel, BorderLayout.CENTER);
    }
}
