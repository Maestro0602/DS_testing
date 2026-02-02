package com.itc.studentmgmt.ui;

import com.itc.studentmgmt.dao.StudentDAO;
import com.itc.studentmgmt.model.Student;
import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.model.UserRole;
import java.awt.*;
import java.util.List;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;

public class MainFrame extends JFrame {
    private User currentUser;
    private StudentDAO studentDAO;
    private JTable studentTable;
    private DefaultTableModel tableModel;
    private JTextField searchField;
    
    // Modern color scheme matching LoginFrame
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color SECONDARY_COLOR = new Color(52, 152, 219);
    private static final Color BACKGROUND_COLOR = new Color(236, 240, 241);
    private static final Color CARD_COLOR = Color.WHITE;
    private static final Color TEXT_COLOR = new Color(44, 62, 80);
    private static final Color LIGHT_TEXT = new Color(127, 140, 141);
    private static final Color HOVER_COLOR = new Color(52, 152, 219);
    private static final Color TABLE_HEADER = new Color(52, 73, 94);
    
    public MainFrame(User user) {
        this.currentUser = user;
        this.studentDAO = new StudentDAO();
        initComponents();
        loadStudents();
    }
    
    private void initComponents() {
        setTitle("Student Management System - ITC");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 750);
        setLocationRelativeTo(null);
        
        // Main container with background color
        JPanel mainContainer = new JPanel(new BorderLayout());
        mainContainer.setBackground(BACKGROUND_COLOR);
        
        // Header panel with gradient
        JPanel headerPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                GradientPaint gp = new GradientPaint(0, 0, PRIMARY_COLOR, getWidth(), 0, SECONDARY_COLOR);
                g2d.setPaint(gp);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        headerPanel.setLayout(new BorderLayout());
        headerPanel.setPreferredSize(new Dimension(getWidth(), 80));
        headerPanel.setBorder(new EmptyBorder(15, 30, 15, 30));
        
        // Left side of header
        JPanel headerLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 0));
        headerLeft.setOpaque(false);
        
        JLabel iconLabel = new JLabel("🎓");
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 32));
        headerLeft.add(iconLabel);
        
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setOpaque(false);
        
        JLabel titleLabel = new JLabel("Student Management System");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        titleLabel.setForeground(Color.WHITE);
        titlePanel.add(titleLabel);
        
        JLabel subtitleLabel = new JLabel("Institute of Technology Cambodia");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subtitleLabel.setForeground(new Color(255, 255, 255, 200));
        titlePanel.add(subtitleLabel);
        
        headerLeft.add(titlePanel);
        headerPanel.add(headerLeft, BorderLayout.WEST);
        
        // Right side of header
        JPanel headerRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 5));
        headerRight.setOpaque(false);
        
        JPanel userPanel = new JPanel();
        userPanel.setLayout(new BoxLayout(userPanel, BoxLayout.Y_AXIS));
        userPanel.setOpaque(false);
        
        JLabel welcomeLabel = new JLabel(currentUser.getUsername());
        welcomeLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        welcomeLabel.setForeground(Color.WHITE);
        welcomeLabel.setAlignmentX(Component.RIGHT_ALIGNMENT);
        userPanel.add(welcomeLabel);
        
        JLabel roleLabel = new JLabel(currentUser.getRole().toString());
        roleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        roleLabel.setForeground(new Color(255, 255, 255, 180));
        roleLabel.setAlignmentX(Component.RIGHT_ALIGNMENT);
        userPanel.add(roleLabel);
        
        headerRight.add(userPanel);
        
        JButton logoutButton = createStyledButton("Logout", false);
        logoutButton.setBackground(new Color(231, 76, 60));
        logoutButton.addActionListener(e -> {
            dispose();
            new LoginFrame().setVisible(true);
        });
        headerRight.add(logoutButton);
        
        headerPanel.add(headerRight, BorderLayout.EAST);
        mainContainer.add(headerPanel, BorderLayout.NORTH);
        
        // Create tabbed pane for role-based navigation
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Segoe UI", Font.BOLD, 13));
        tabbedPane.setBackground(BACKGROUND_COLOR);
        
        // Add Student Management tab (for all users)
        tabbedPane.addTab("📚 Students", createStudentManagementPanel());
        
        // Add Teacher Panel tab (for Teachers and Admins)
        if (currentUser.getRole() == UserRole.TEACHER || currentUser.getRole() == UserRole.ADMIN) {
            TeacherPanel teacherPanel = new TeacherPanel(currentUser);
            tabbedPane.addTab("👨‍🏫 Teacher Dashboard", teacherPanel);
        }
        
        // Add Admin Panel placeholder (for Admins only)
        if (currentUser.getRole() == UserRole.ADMIN) {
            tabbedPane.addTab("⚙️ Admin Settings", createAdminPanel());
        }
        
        mainContainer.add(tabbedPane, BorderLayout.CENTER);
        add(mainContainer);
    }
    
    private JPanel createStudentManagementPanel() {
        // Content panel
        JPanel contentPanel = new JPanel(new BorderLayout(20, 20));
        contentPanel.setBackground(BACKGROUND_COLOR);
        contentPanel.setBorder(new EmptyBorder(25, 30, 25, 30));
        
        // Control panel card
        JPanel controlCard = new JPanel();
        controlCard.setBackground(CARD_COLOR);
        controlCard.setLayout(new BorderLayout(15, 15));
        controlCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1),
            new EmptyBorder(20, 25, 20, 25)
        ));
        
        // Action buttons panel
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        actionsPanel.setBackground(CARD_COLOR);
        
        if (currentUser.getRole() == UserRole.ADMIN || 
            currentUser.getRole() == UserRole.TEACHER) {
            JButton addButton = createStyledButton("➕ Add Student", true);
            addButton.addActionListener(e -> showAddDialog());
            actionsPanel.add(addButton);
            
            JButton editButton = createStyledButton("✏️ Edit Student", true);
            editButton.addActionListener(e -> showEditDialog());
            actionsPanel.add(editButton);
            
            JButton deleteButton = createStyledButton("🗑️ Delete Student", true);
            deleteButton.setBackground(new Color(231, 76, 60));
            deleteButton.addActionListener(e -> deleteStudent());
            actionsPanel.add(deleteButton);
            
            actionsPanel.add(createSeparator());
        }
        
        JButton refreshButton = createStyledButton("🔄 Refresh", true);
        refreshButton.addActionListener(e -> loadStudents());
        actionsPanel.add(refreshButton);
        
        controlCard.add(actionsPanel, BorderLayout.WEST);
        
        // Search panel
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        searchPanel.setBackground(CARD_COLOR);
        
        JLabel searchLabel = new JLabel("🔍");
        searchLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 16));
        searchPanel.add(searchLabel);
        
        searchField = new JTextField(25);
        searchField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        searchField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199), 1),
            new EmptyBorder(8, 12, 8, 12)
        ));
        searchField.addActionListener(e -> searchStudents());
        searchPanel.add(searchField);
        
        JButton searchButton = createStyledButton("Search", true);
        searchButton.addActionListener(e -> searchStudents());
        searchPanel.add(searchButton);
        
        controlCard.add(searchPanel, BorderLayout.EAST);
        contentPanel.add(controlCard, BorderLayout.NORTH);
        
        // Table card
        JPanel tableCard = new JPanel(new BorderLayout());
        tableCard.setBackground(CARD_COLOR);
        tableCard.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 10), 1),
            new EmptyBorder(0, 0, 0, 0)
        ));
        
        // Table with all student fields
        String[] columns = {"Student ID", "Name", "Email", "Major", "Phone", "GPA", "Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        studentTable = new JTable(tableModel);
        studentTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        studentTable.setRowHeight(40);
        studentTable.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        studentTable.setSelectionBackground(new Color(52, 152, 219, 50));
        studentTable.setSelectionForeground(TEXT_COLOR);
        studentTable.setShowVerticalLines(false);
        studentTable.setIntercellSpacing(new Dimension(0, 0));
        
        // Style table header
        JTableHeader header = studentTable.getTableHeader();
        header.setBackground(TABLE_HEADER);
        header.setForeground(Color.WHITE);
        header.setFont(new Font("Segoe UI", Font.BOLD, 13));
        header.setPreferredSize(new Dimension(header.getPreferredSize().width, 45));
        header.setReorderingAllowed(false);
        
        // Center align cells
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < studentTable.getColumnCount(); i++) {
            studentTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
        
        // Alternating row colors
        studentTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(248, 249, 250));
                }
                setHorizontalAlignment(JLabel.CENTER);
                setBorder(new EmptyBorder(5, 10, 5, 10));
                return c;
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(studentTable);
        scrollPane.setBorder(null);
        scrollPane.getViewport().setBackground(Color.WHITE);
        tableCard.add(scrollPane, BorderLayout.CENTER);
        
        contentPanel.add(tableCard, BorderLayout.CENTER);
        
        return contentPanel;
    }
    
    private JPanel createAdminPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 20));
        panel.setBackground(BACKGROUND_COLOR);
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        // Header card with stats
        JPanel headerCard = new JPanel();
        headerCard.setBackground(CARD_COLOR);
        headerCard.setBorder(new EmptyBorder(20, 25, 20, 25));
        headerCard.setLayout(new BoxLayout(headerCard, BoxLayout.Y_AXIS));
        
        JLabel titleLabel = new JLabel("⚙️ Admin Settings");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        headerCard.add(titleLabel);
        
        headerCard.add(Box.createVerticalStrut(10));
        
        JLabel infoLabel = new JLabel("Manage system settings, users, and security configurations.");
        infoLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        infoLabel.setForeground(LIGHT_TEXT);
        infoLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        headerCard.add(infoLabel);
        
        headerCard.add(Box.createVerticalStrut(20));
        
        // Stats panel
        JPanel statsPanel = new JPanel(new GridLayout(1, 4, 15, 0));
        statsPanel.setBackground(CARD_COLOR);
        statsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        statsPanel.setMaximumSize(new Dimension(1000, 80));
        
        // Get user counts
        com.itc.studentmgmt.dao.UserDAO userDAO = new com.itc.studentmgmt.dao.UserDAO();
        int teacherCount = userDAO.countUsersByRole(UserRole.TEACHER);
        int studentUserCount = userDAO.countUsersByRole(UserRole.STUDENT);
        
        statsPanel.add(createStatCard("👥 Total Students", String.valueOf(studentDAO.countStudents())));
        statsPanel.add(createStatCard("👨‍🏫 Teachers", String.valueOf(teacherCount)));
        statsPanel.add(createStatCard("🔐 Security Status", "Active"));
        statsPanel.add(createStatCard("📊 System Health", "OK"));
        
        headerCard.add(statsPanel);
        panel.add(headerCard, BorderLayout.NORTH);
        
        // User Management Panel
        UserManagementPanel userMgmtPanel = new UserManagementPanel(currentUser);
        panel.add(userMgmtPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatCard(String title, String value) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(new Color(236, 240, 241));
        card.setBorder(new EmptyBorder(15, 20, 15, 20));
        
        JLabel titleL = new JLabel(title);
        titleL.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        titleL.setForeground(LIGHT_TEXT);
        card.add(titleL);
        
        JLabel valueL = new JLabel(value);
        valueL.setFont(new Font("Segoe UI", Font.BOLD, 24));
        valueL.setForeground(PRIMARY_COLOR);
        card.add(valueL);
        
        return card;
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
        
        Color originalColor = button.getBackground();
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                if (originalColor.equals(PRIMARY_COLOR)) {
                    button.setBackground(HOVER_COLOR);
                } else if (originalColor.equals(new Color(231, 76, 60))) {
                    button.setBackground(new Color(192, 57, 43));
                } else {
                    button.setBackground(new Color(127, 140, 141));
                }
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(originalColor);
            }
        });
        
        return button;
    }
    
    private Component createSeparator() {
        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
        separator.setPreferredSize(new Dimension(1, 30));
        separator.setForeground(new Color(189, 195, 199));
        return separator;
    }
    
    private void loadStudents() {
        tableModel.setRowCount(0);
        List<Student> students = studentDAO.getAllStudents();
        
        for (Student student : students) {
            tableModel.addRow(new Object[]{
                student.getStudentId(),
                student.getName(),
                student.getEmail(),
                student.getMajor(),
                student.getPhone() != null ? student.getPhone() : "-",
                String.format("%.2f", student.getGpa()),
                student.getStatus() != null ? student.getStatus() : "ACTIVE"
            });
        }
    }
    
    private void searchStudents() {
        String keyword = searchField.getText().trim();
        tableModel.setRowCount(0);
        
        List<Student> students;
        if (keyword.isEmpty()) {
            students = studentDAO.getAllStudents();
        } else {
            students = studentDAO.searchStudents(keyword);
        }
        
        for (Student student : students) {
            tableModel.addRow(new Object[]{
                student.getStudentId(),
                student.getName(),
                student.getEmail(),
                student.getMajor(),
                student.getPhone() != null ? student.getPhone() : "-",
                String.format("%.2f", student.getGpa()),
                student.getStatus() != null ? student.getStatus() : "ACTIVE"
            });
        }
    }
    
    private void showAddDialog() {
        JDialog dialog = createStyledDialog("Add New Student");
        dialog.setSize(550, 600);
        
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(new EmptyBorder(30, 40, 30, 40));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);
        
        JTextField idField = createStyledTextField();
        JTextField nameField = createStyledTextField();
        JTextField emailField = createStyledTextField();
        JTextField majorField = createStyledTextField();
        JTextField phoneField = createStyledTextField();
        JTextField addressField = createStyledTextField();
        JTextField gpaField = createStyledTextField();
        gpaField.setText("0.00");
        String[] statuses = {"ACTIVE", "INACTIVE", "GRADUATED", "SUSPENDED"};
        JComboBox<String> statusCombo = new JComboBox<>(statuses);
        statusCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        
        addFormField(panel, gbc, 0, "Student ID *:", idField);
        addFormField(panel, gbc, 1, "Name *:", nameField);
        addFormField(panel, gbc, 2, "Email *:", emailField);
        addFormField(panel, gbc, 3, "Major *:", majorField);
        addFormField(panel, gbc, 4, "Phone 🔒:", phoneField);
        addFormField(panel, gbc, 5, "Address 🔒:", addressField);
        addFormField(panel, gbc, 6, "GPA:", gpaField);
        
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 1;
        JLabel statusLabel = new JLabel("Status:");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        panel.add(statusLabel, gbc);
        gbc.gridx = 1;
        panel.add(statusCombo, gbc);
        
        // Info label about encryption
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        JLabel encLabel = new JLabel("🔒 = Encrypted fields (Phone & Address)");
        encLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        encLabel.setForeground(new Color(39, 174, 96));
        panel.add(encLabel, gbc);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        buttonPanel.setBackground(Color.WHITE);
        
        JButton saveButton = createStyledButton("Save Student", true);
        saveButton.addActionListener(e -> {
            String id = idField.getText().trim();
            String name = nameField.getText().trim();
            String email = emailField.getText().trim();
            String major = majorField.getText().trim();
            
            if (id.isEmpty() || name.isEmpty() || email.isEmpty() || major.isEmpty()) {
                showStyledMessage(dialog, "Required fields (*) cannot be empty", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            Student student = new Student(id, name, email, major);
            student.setPhone(phoneField.getText().trim());
            student.setAddress(addressField.getText().trim());
            try {
                student.setGpa(Double.parseDouble(gpaField.getText().trim()));
            } catch (NumberFormatException ex) {
                student.setGpa(0.0);
            }
            student.setStatus((String) statusCombo.getSelectedItem());
            
            if (studentDAO.addStudent(student)) {
                showStyledMessage(dialog, "Student added successfully!\n(Sensitive data encrypted)", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadStudents();
                dialog.dispose();
            } else {
                // Show specific error message based on error code
                String errorMsg;
                switch (studentDAO.getLastErrorCode()) {
                    case StudentDAO.ERROR_DUPLICATE_ID:
                        errorMsg = "Student ID '" + id + "' already exists!\nPlease use a different Student ID.";
                        break;
                    case StudentDAO.ERROR_DUPLICATE_EMAIL:
                        errorMsg = "Email '" + email + "' is already registered!\nPlease use a different email address.";
                        break;
                    case StudentDAO.ERROR_DATABASE:
                        errorMsg = "Database error: " + studentDAO.getLastErrorMessage();
                        break;
                    default:
                        errorMsg = "Failed to add student. " + studentDAO.getLastErrorMessage();
                }
                showStyledMessage(dialog, errorMsg, "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton cancelButton = createStyledButton("Cancel", false);
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        
        gbc.gridx = 0;
        gbc.gridy = 9;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 8, 8, 8);
        panel.add(buttonPanel, gbc);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void showEditDialog() {
        int row = studentTable.getSelectedRow();
        if (row == -1) {
            showStyledMessage(this, "Please select a student to edit", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String studentId = (String) tableModel.getValueAt(row, 0);
        Student student = studentDAO.getStudent(studentId);
        
        if (student == null) {
            showStyledMessage(this, "Student not found", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        JDialog dialog = createStyledDialog("Edit Student");
        dialog.setSize(550, 600);
        
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(new EmptyBorder(30, 40, 30, 40));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);
        
        JTextField nameField = createStyledTextField();
        nameField.setText(student.getName());
        JTextField emailField = createStyledTextField();
        emailField.setText(student.getEmail());
        JTextField majorField = createStyledTextField();
        majorField.setText(student.getMajor());
        JTextField phoneField = createStyledTextField();
        phoneField.setText(student.getPhone() != null ? student.getPhone() : "");
        JTextField addressField = createStyledTextField();
        addressField.setText(student.getAddress() != null ? student.getAddress() : "");
        JTextField gpaField = createStyledTextField();
        gpaField.setText(String.format("%.2f", student.getGpa()));
        String[] statuses = {"ACTIVE", "INACTIVE", "GRADUATED", "SUSPENDED"};
        JComboBox<String> statusCombo = new JComboBox<>(statuses);
        statusCombo.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        statusCombo.setSelectedItem(student.getStatus() != null ? student.getStatus() : "ACTIVE");
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        JLabel idLabel = new JLabel("Student ID:");
        idLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        panel.add(idLabel, gbc);
        gbc.gridx = 1;
        JLabel idValue = new JLabel(student.getStudentId());
        idValue.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        idValue.setForeground(LIGHT_TEXT);
        panel.add(idValue, gbc);
        
        addFormField(panel, gbc, 1, "Name *:", nameField);
        addFormField(panel, gbc, 2, "Email *:", emailField);
        addFormField(panel, gbc, 3, "Major *:", majorField);
        addFormField(panel, gbc, 4, "Phone 🔒:", phoneField);
        addFormField(panel, gbc, 5, "Address 🔒:", addressField);
        addFormField(panel, gbc, 6, "GPA:", gpaField);
        
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 1;
        JLabel statusLabel = new JLabel("Status:");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        panel.add(statusLabel, gbc);
        gbc.gridx = 1;
        panel.add(statusCombo, gbc);
        
        // Info label about encryption
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        JLabel encLabel = new JLabel("🔒 = Encrypted fields (Phone & Address)");
        encLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        encLabel.setForeground(new Color(39, 174, 96));
        panel.add(encLabel, gbc);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        buttonPanel.setBackground(Color.WHITE);
        
        JButton saveButton = createStyledButton("Update Student", true);
        saveButton.addActionListener(e -> {
            student.setName(nameField.getText().trim());
            student.setEmail(emailField.getText().trim());
            student.setMajor(majorField.getText().trim());
            student.setPhone(phoneField.getText().trim());
            student.setAddress(addressField.getText().trim());
            try {
                student.setGpa(Double.parseDouble(gpaField.getText().trim()));
            } catch (NumberFormatException ex) {
                student.setGpa(0.0);
            }
            student.setStatus((String) statusCombo.getSelectedItem());
            
            if (studentDAO.updateStudent(student)) {
                showStyledMessage(dialog, "Student updated successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadStudents();
                dialog.dispose();
            } else {
                // Show specific error message based on error code
                String errorMsg;
                switch (studentDAO.getLastErrorCode()) {
                    case StudentDAO.ERROR_DUPLICATE_EMAIL:
                        errorMsg = "Email '" + student.getEmail() + "' is already registered to another student!\nPlease use a different email address.";
                        break;
                    case StudentDAO.ERROR_DATABASE:
                        errorMsg = "Database error: " + studentDAO.getLastErrorMessage();
                        break;
                    default:
                        errorMsg = "Failed to update student. " + studentDAO.getLastErrorMessage();
                }
                showStyledMessage(dialog, errorMsg, "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton cancelButton = createStyledButton("Cancel", false);
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        
        gbc.gridx = 0;
        gbc.gridy = 9;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 8, 8, 8);
        panel.add(buttonPanel, gbc);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void deleteStudent() {
        int row = studentTable.getSelectedRow();
        if (row == -1) {
            showStyledMessage(this, "Please select a student to delete", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String studentId = (String) tableModel.getValueAt(row, 0);
        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to delete this student?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (studentDAO.deleteStudent(studentId)) {
                showStyledMessage(this, "Student deleted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                loadStudents();
            } else {
                showStyledMessage(this, "Failed to delete student", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private JDialog createStyledDialog(String title) {
        JDialog dialog = new JDialog(this, title, true);
        dialog.setSize(500, 450);
        dialog.setLocationRelativeTo(this);
        dialog.setResizable(false);
        return dialog;
    }
    
    private JTextField createStyledTextField() {
        JTextField field = new JTextField(20);
        field.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199), 1),
            new EmptyBorder(8, 12, 8, 12)
        ));
        return field;
    }
    
    private void addFormField(JPanel panel, GridBagConstraints gbc, int row, String labelText, JTextField field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        JLabel label = new JLabel(labelText);
        label.setFont(new Font("Segoe UI", Font.BOLD, 13));
        label.setForeground(TEXT_COLOR);
        panel.add(label, gbc);
        
        gbc.gridx = 1;
        panel.add(field, gbc);
    }
    
    private void showStyledMessage(Component parent, String message, String title, int messageType) {
        JOptionPane.showMessageDialog(parent, message, title, messageType);
    }
}