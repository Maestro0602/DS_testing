package com.itc.studentmgmt.security;

/**
 * 🧪 SECURITY SIMULATION TEST RUNNER
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Simple test runner to execute the MaxSecurityAttackSimulation.
 * 
 * This demonstrates the security system's defensive capabilities by
 * running a safe, multi-phase adversary simulation.
 * 
 * @author Security Testing Team
 * @version 1.0.0
 */
public class SecuritySimulationRunner {
    
    public static void main(String[] args) {
        System.out.println();
        System.out.println("╔═══════════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║  🛡️ STUDENT MANAGEMENT SYSTEM - SECURITY DEFENSIVE TESTING                        ║");
        System.out.println("╠═══════════════════════════════════════════════════════════════════════════════════╣");
        System.out.println("║  This program runs a SAFE adversary simulation to test the security features:    ║");
        System.out.println("║                                                                                   ║");
        System.out.println("║    ✓ Intrusion Detection System (IDS)                                            ║");
        System.out.println("║    ✓ Rate Limiting (IP-based and User-based)                                     ║");
        System.out.println("║    ✓ Brute Force Attack Detection                                                ║");
        System.out.println("║    ✓ SQL Injection Pattern Detection                                             ║");
        System.out.println("║    ✓ XSS Attack Detection                                                        ║");
        System.out.println("║    ✓ Session Token Validation                                                    ║");
        System.out.println("║    ✓ Threat Scoring System                                                       ║");
        System.out.println("║    ✓ Security Audit Logging                                                      ║");
        System.out.println("║    ✓ Alert Generation                                                            ║");
        System.out.println("║    ✓ Abnormal Behavior Detection                                                 ║");
        System.out.println("║                                                                                   ║");
        System.out.println("║  ⚠️ SAFE SIMULATION: No real attacks or harmful operations are performed          ║");
        System.out.println("╚═══════════════════════════════════════════════════════════════════════════════════╝");
        System.out.println();
        
        // Parse command line arguments
        String mode = args.length > 0 ? args[0].toLowerCase() : "full";
        
        MaxSecurityAttackSimulation simulation = new MaxSecurityAttackSimulation();
        
        switch (mode) {
            case "1", "recon", "reconnaissance" -> {
                System.out.println("▶️ Running Phase 1: Reconnaissance only\n");
                simulation.runPhase1Only();
            }
            case "2", "cred", "credential" -> {
                System.out.println("▶️ Running Phase 2: Credential Stuffing only\n");
                simulation.runPhase2Only();
            }
            case "3", "inject", "injection" -> {
                System.out.println("▶️ Running Phase 3: Injection Attempts only\n");
                simulation.runPhase3Only();
            }
            case "4", "session", "token" -> {
                System.out.println("▶️ Running Phase 4: Session Token Abuse only\n");
                simulation.runPhase4Only();
            }
            case "5", "ransom", "exfil" -> {
                System.out.println("▶️ Running Phase 5: Ransomware-Like Behavior (SAFE) only\n");
                simulation.runPhase5Only();
            }
            case "full", "all" -> {
                System.out.println("▶️ Running FULL multi-phase simulation\n");
                simulation.runFullSimulation();
            }
            case "help", "-h", "--help" -> {
                printUsage();
            }
            default -> {
                System.out.println("❌ Unknown mode: " + mode);
                System.out.println();
                printUsage();
            }
        }
        
        System.out.println();
        System.out.println("═══════════════════════════════════════════════════════════════════════════════════");
        System.out.println("✅ Security simulation completed. Check the security_logs folder for audit logs.");
        System.out.println("═══════════════════════════════════════════════════════════════════════════════════");
    }
    
    private static void printUsage() {
        System.out.println("Usage: java SecuritySimulationRunner [mode]");
        System.out.println();
        System.out.println("Modes:");
        System.out.println("  full, all      - Run the complete multi-phase simulation (default)");
        System.out.println("  1, recon       - Phase 1: Reconnaissance");
        System.out.println("  2, cred        - Phase 2: Credential Stuffing");
        System.out.println("  3, inject      - Phase 3: Injection Attempts");
        System.out.println("  4, session     - Phase 4: Session Token Abuse");
        System.out.println("  5, ransom      - Phase 5: Ransomware-Like Behavior (SAFE)");
        System.out.println("  help           - Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java SecuritySimulationRunner            # Run full simulation");
        System.out.println("  java SecuritySimulationRunner 3          # Run injection testing only");
        System.out.println("  java SecuritySimulationRunner inject     # Run injection testing only");
    }
}
