package com.itc.studentmgmt.ui;

import com.itc.studentmgmt.model.User;
import com.itc.studentmgmt.security.TwoFactorAuthService;
import com.itc.studentmgmt.service.AuthenticationService;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

public class LoginFrame extends JFrame {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private final AuthenticationService authService;
    
    // Modern color scheme
    private static final Color PRIMARY_COLOR = new Color(41, 128, 185);
    private static final Color SECONDARY_COLOR = new Color(52, 152, 219);
    private static final Color BACKGROUND_COLOR = new Color(236, 240, 241);
    @SuppressWarnings("unused") // Reserved for potential card background customization
    private static final Color CARD_COLOR = Color.WHITE;
    private static final Color TEXT_COLOR = new Color(44, 62, 80);
    private static final Color LIGHT_TEXT = new Color(127, 140, 141);
    
    public LoginFrame() {
        authService = new AuthenticationService();
        initComponents();
    }
    
    private void initComponents() {
        setTitle("Student Management System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 600);
        setLocationRelativeTo(null);
        setResizable(false);
        
        // Set the frame's content pane background color
        getContentPane().setBackground(BACKGROUND_COLOR);
        
        // Main container with solid background
        JPanel backgroundPanel = new JPanel();
        backgroundPanel.setBackground(BACKGROUND_COLOR);
        backgroundPanel.setLayout(new GridBagLayout());
        
        // Card panel for login form with gradient
        JPanel cardPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                // Subtle gradient on the card
                GradientPaint gp = new GradientPaint(0, 0, Color.WHITE, 0, getHeight(), new Color(248, 249, 250));
                g2d.setPaint(gp);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        cardPanel.setLayout(new BoxLayout(cardPanel, BoxLayout.Y_AXIS));
        cardPanel.setBorder(new EmptyBorder(40, 50, 40, 50));
        cardPanel.setPreferredSize(new Dimension(400, 500));
        
        // Add shadow effect with rounded appearance
        cardPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 0, 0, 30), 1, true),
            new EmptyBorder(40, 50, 40, 50)
        ));
        
        // Logo/Icon area with gradient background
        JPanel iconPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                GradientPaint gp = new GradientPaint(0, 0, PRIMARY_COLOR, getWidth(), getHeight(), SECONDARY_COLOR);
                g2d.setPaint(gp);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 50, 50);
            }
        };
        iconPanel.setOpaque(false);
        iconPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        iconPanel.setPreferredSize(new Dimension(100, 100));
        iconPanel.setMaximumSize(new Dimension(100, 100));
        
        JLabel iconLabel = new JLabel("🎓");
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 50));
        iconPanel.add(iconLabel);
        
        // Center the icon panel
        JPanel iconContainer = new JPanel(new FlowLayout(FlowLayout.CENTER));
        iconContainer.setOpaque(false);
        iconContainer.add(iconPanel);
        iconContainer.setMaximumSize(new Dimension(400, 120));
        cardPanel.add(iconContainer);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        
        // Title
        JLabel titleLabel = new JLabel("Student Management");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        cardPanel.add(titleLabel);
        
        // Subtitle
        JLabel subtitleLabel = new JLabel("Institute of Technology Cambodia");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        subtitleLabel.setForeground(LIGHT_TEXT);
        subtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        cardPanel.add(subtitleLabel);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 30)));
        
        // Username field
        JLabel usernameLabel = new JLabel("Username");
        usernameLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        usernameLabel.setForeground(TEXT_COLOR);
        usernameLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        cardPanel.add(usernameLabel);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        
        usernameField = new JTextField(20);
        usernameField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        usernameField.setMaximumSize(new Dimension(400, 40));
        usernameField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199), 1),
            new EmptyBorder(8, 12, 8, 12)
        ));
        cardPanel.add(usernameField);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // Password field
        JLabel passwordLabel = new JLabel("Password");
        passwordLabel.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        passwordLabel.setForeground(TEXT_COLOR);
        passwordLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        cardPanel.add(passwordLabel);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        
        passwordField = new JPasswordField(20);
        passwordField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        passwordField.setMaximumSize(new Dimension(400, 40));
        passwordField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199), 1),
            new EmptyBorder(8, 12, 8, 12)
        ));
        passwordField.addActionListener(e -> handleLogin());
        cardPanel.add(passwordField);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 30)));
        
        // Login button with gradient
        JButton loginButton = new JButton("LOGIN") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                if (getModel().isPressed()) {
                    g2d.setColor(PRIMARY_COLOR.darker());
                } else if (getModel().isRollover()) {
                    GradientPaint gp = new GradientPaint(0, 0, SECONDARY_COLOR, getWidth(), 0, PRIMARY_COLOR);
                    g2d.setPaint(gp);
                } else {
                    GradientPaint gp = new GradientPaint(0, 0, PRIMARY_COLOR, getWidth(), 0, SECONDARY_COLOR);
                    g2d.setPaint(gp);
                }
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                
                g2d.setColor(Color.WHITE);
                g2d.setFont(getFont());
                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = ((getHeight() - fm.getHeight()) / 2) + fm.getAscent();
                g2d.drawString(getText(), x, y);
            }
        };
        loginButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
        loginButton.setForeground(Color.WHITE);
        loginButton.setFocusPainted(false);
        loginButton.setBorderPainted(false);
        loginButton.setContentAreaFilled(false);
        loginButton.setMaximumSize(new Dimension(400, 45));
        loginButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        loginButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        loginButton.addActionListener(e -> handleLogin());
        cardPanel.add(loginButton);
        
        cardPanel.add(Box.createRigidArea(new Dimension(0, 25)));
        
        // Demo accounts info
        JLabel infoLabel = new JLabel("<html><div style='text-align: center;'>"
            + "<span style='color: #95a5a6; font-size: 11px;'>Demo Accounts</span><br/>"
            + "<span style='color: #7f8c8d; font-size: 10px;'>Admin: admin / admin123</span><br/>"
            + "<span style='color: #7f8c8d; font-size: 10px;'>Teacher: teacher1 / teacher123</span>"
            + "</div></html>");
        infoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        cardPanel.add(infoLabel);
        
        backgroundPanel.add(cardPanel);
        add(backgroundPanel);
    }
    
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        if (username.isEmpty() || password.isEmpty()) {
            showErrorDialog("Please enter both username and password");
            return;
        }
        
        // Check if 2FA is enabled and configured
        if (authService.isTwoFactorEnabled()) {
            // Step 1: Validate credentials first
            User user = authService.validateCredentials(username, password);
            
            if (user != null) {
                // Step 2: Send 2FA code
                TwoFactorAuthService.TwoFactorResult sendResult = authService.send2FACode(username);
                
                if (sendResult == TwoFactorAuthService.TwoFactorResult.SUCCESS) {
                    // Step 3: Show 2FA dialog
                    show2FADialog(username);
                } else if (sendResult == TwoFactorAuthService.TwoFactorResult.NOT_CONFIGURED) {
                    // 2FA not configured, fall back to regular login
                    User loggedInUser = authService.login(username, password);
                    if (loggedInUser != null) {
                        dispose();
                        new EnhancedMainFrame(loggedInUser).setVisible(true);
                    } else {
                        showErrorDialog("Login failed");
                        passwordField.setText("");
                    }
                } else {
                    showErrorDialog("Failed to send verification code. Please try again.");
                }
            } else {
                showErrorDialog("Invalid username or password");
                passwordField.setText("");
            }
        } else {
            // Regular login without 2FA
            User user = authService.login(username, password);
            if (user != null) {
                dispose();
                new EnhancedMainFrame(user).setVisible(true);
            } else {
                showErrorDialog("Invalid username or password");
                passwordField.setText("");
            }
        }
    }
    
    /**
     * Show 2FA verification dialog
     */
    private void show2FADialog(String username) {
        // Create 2FA dialog
        JDialog dialog = new JDialog(this, "Two-Factor Authentication", true);
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);
        dialog.setResizable(false);
        
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(30, 40, 30, 40));
        panel.setBackground(BACKGROUND_COLOR);
        
        // Icon
        JLabel iconLabel = new JLabel("🔐");
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 40));
        iconLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(iconLabel);
        
        panel.add(Box.createRigidArea(new Dimension(0, 15)));
        
        // Title
        JLabel titleLabel = new JLabel("Verification Required");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(TEXT_COLOR);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(titleLabel);
        
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        
        // Message
        JLabel messageLabel = new JLabel("<html><div style='text-align: center;'>" +
            "A verification code has been sent to your<br/>" +
            "Telegram/Discord. Enter the code below:</div></html>");
        messageLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        messageLabel.setForeground(LIGHT_TEXT);
        messageLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(messageLabel);
        
        panel.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // Code input field
        JTextField codeField = new JTextField(6);
        codeField.setFont(new Font("Segoe UI", Font.BOLD, 24));
        codeField.setHorizontalAlignment(JTextField.CENTER);
        codeField.setMaximumSize(new Dimension(200, 50));
        codeField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(PRIMARY_COLOR, 2),
            new EmptyBorder(10, 15, 10, 15)
        ));
        panel.add(codeField);
        
        panel.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // Verify button
        JButton verifyButton = new JButton("VERIFY") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                if (getModel().isPressed()) {
                    g2d.setColor(PRIMARY_COLOR.darker());
                } else {
                    GradientPaint gp = new GradientPaint(0, 0, PRIMARY_COLOR, getWidth(), 0, SECONDARY_COLOR);
                    g2d.setPaint(gp);
                }
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                
                g2d.setColor(Color.WHITE);
                g2d.setFont(getFont());
                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = ((getHeight() - fm.getHeight()) / 2) + fm.getAscent();
                g2d.drawString(getText(), x, y);
            }
        };
        verifyButton.setFont(new Font("Segoe UI", Font.BOLD, 14));
        verifyButton.setForeground(Color.WHITE);
        verifyButton.setFocusPainted(false);
        verifyButton.setBorderPainted(false);
        verifyButton.setContentAreaFilled(false);
        verifyButton.setMaximumSize(new Dimension(200, 40));
        verifyButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        verifyButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        verifyButton.addActionListener(e -> {
            String code = codeField.getText().trim();
            if (code.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, 
                    "Please enter the verification code", 
                    "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            TwoFactorAuthService.TwoFactorResult result = authService.verify2FACode(username, code);
            
            switch (result) {
                case SUCCESS:
                    dialog.dispose();
                    // Complete login after successful 2FA
                    User user = authService.completeLoginAfter2FA(username, "0.0.0.0", "Desktop App");
                    if (user != null) {
                        dispose();
                        new EnhancedMainFrame(user).setVisible(true);
                    } else {
                        showErrorDialog("Login failed after verification");
                    }
                    break;
                    
                case INVALID_CODE:
                    JOptionPane.showMessageDialog(dialog,
                        "Invalid verification code. Please try again.",
                        "Verification Failed", JOptionPane.ERROR_MESSAGE);
                    codeField.setText("");
                    break;
                    
                case CODE_EXPIRED:
                    JOptionPane.showMessageDialog(dialog,
                        "Verification code has expired. Please login again.",
                        "Code Expired", JOptionPane.ERROR_MESSAGE);
                    dialog.dispose();
                    break;
                    
                case TOO_MANY_ATTEMPTS:
                    JOptionPane.showMessageDialog(dialog,
                        "Too many failed attempts. Please login again.",
                        "Verification Blocked", JOptionPane.ERROR_MESSAGE);
                    dialog.dispose();
                    break;
                    
                default:
                    JOptionPane.showMessageDialog(dialog,
                        "Verification failed. Please try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // Allow Enter key to verify
        codeField.addActionListener(e -> verifyButton.doClick());
        
        panel.add(verifyButton);
        
        panel.add(Box.createRigidArea(new Dimension(0, 15)));
        
        // Resend link
        JLabel resendLabel = new JLabel("<html><u>Resend Code</u></html>");
        resendLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        resendLabel.setForeground(PRIMARY_COLOR);
        resendLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        resendLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        resendLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                TwoFactorAuthService.TwoFactorResult result = authService.send2FACode(username);
                if (result == TwoFactorAuthService.TwoFactorResult.SUCCESS) {
                    JOptionPane.showMessageDialog(dialog,
                        "A new verification code has been sent.",
                        "Code Sent", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(dialog,
                        "Failed to resend code. Please try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        panel.add(resendLabel);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void showErrorDialog(String message) {
        JOptionPane.showMessageDialog(this,
            message,
            "Login Error",
            JOptionPane.ERROR_MESSAGE);
    }
}