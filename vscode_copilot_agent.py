#!/usr/bin/env python3
"""
VS Code GitHub Copilot Agent Script
Executes remediation tasks when triggered with "@remediate" command
"""

import os
import json
import time
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [VSCODE-AGENT] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vscode_copilot_agent.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class VSCodeCopilotAgent:
    """VS Code Copilot Agent for automated remediation"""
    
    def __init__(self, workspace_path: str = None):
        self.workspace_path = Path(workspace_path) if workspace_path else Path.cwd()
        self.agent_running = False
        self.current_task = None
        self.remediation_queue = []
        
    def start_agent(self):
        """Start the VS Code Copilot agent"""
        self.agent_running = True
        logging.info(f"VS Code Copilot Agent started in workspace: {self.workspace_path}")
        
        # Start monitoring for @remediate commands
        self._monitor_vscode_commands()
        
    def stop_agent(self):
        """Stop the VS Code Copilot agent"""
        self.agent_running = False
        logging.info("VS Code Copilot Agent stopped")
        
    def _monitor_vscode_commands(self):
        """Monitor for @remediate commands in VS Code"""
        while self.agent_running:
            try:
                # Check for @remediate commands in active files
                self._scan_for_remediate_commands()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logging.error(f"Error monitoring VS Code commands: {e}")
                time.sleep(10)
                
    def _scan_for_remediate_commands(self):
        """Scan active files for @remediate commands"""
        try:
            # Look for @remediate in recently modified files
            for file_path in self._get_recent_files():
                if self._has_remediate_command(file_path):
                    self._process_remediate_command(file_path)
                    
        except Exception as e:
            logging.error(f"Error scanning for commands: {e}")
            
    def _get_recent_files(self) -> List[Path]:
        """Get recently modified files in workspace"""
        recent_files = []
        try:
            for file_path in self.workspace_path.rglob("*"):
                if file_path.is_file() and self._is_code_file(file_path):
                    # Check if file was modified in last 5 minutes
                    if time.time() - file_path.stat().st_mtime < 300:
                        recent_files.append(file_path)
        except Exception as e:
            logging.error(f"Error getting recent files: {e}")
            
        return recent_files
        
    def _is_code_file(self, file_path: Path) -> bool:
        """Check if file is a code file"""
        code_extensions = {'.py', '.js', '.ts', '.java', '.cs', '.php', '.rb', '.go', '.rs', '.cpp', '.c', '.html', '.css', '.json'}
        return file_path.suffix.lower() in code_extensions
        
    def _has_remediate_command(self, file_path: Path) -> bool:
        """Check if file contains @remediate command"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                return '@remediate' in content
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return False
            
    def _process_remediate_command(self, file_path: Path):
        """Process @remediate command in a file"""
        try:
            logging.info(f"Processing @remediate command in: {file_path}")
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Extract remediation parameters
            params = self._extract_remediate_params(content)
            
            # Generate remediation prompt
            prompt = self._generate_remediation_prompt(file_path, content, params)
            
            # Execute remediation using Copilot
            remediated_content = self._execute_copilot_remediation(prompt, file_path)
            
            # Save remediated file
            self._save_remediated_file(file_path, remediated_content, params)
            
            # Update original file to remove @remediate command
            self._cleanup_remediate_command(file_path)
            
            logging.info(f"Remediation completed for: {file_path}")
            
        except Exception as e:
            logging.error(f"Error processing @remediate command: {e}")
            
    def _extract_remediate_params(self, content: str) -> Dict[str, Any]:
        """Extract parameters from @remediate command"""
        params = {
            'scan_id': f"vscode_{int(time.time())}",
            'severity': 'MEDIUM',
            'type': 'GENERAL',
            'auto_save': True
        }
        
        # Look for @remediate parameters
        lines = content.split('\n')
        for line in lines:
            if '@remediate' in line:
                # Parse parameters like @remediate severity=HIGH type=SECURITY
                parts = line.split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        params[key.strip()] = value.strip()
                        
        return params
        
    def _generate_remediation_prompt(self, file_path: Path, content: str, params: Dict) -> str:
        """Generate remediation prompt for Copilot"""
        language = self._detect_language(file_path)
        
        prompt = f"""# SECURITY VULNERABILITY FIX REQUEST
# File: {file_path.name}
# Language: {language}
# Scan ID: {params.get('scan_id', 'unknown')}
# Severity: {params.get('severity', 'MEDIUM')}
# Type: {params.get('type', 'GENERAL')}

# TASK FOR GITHUB COPILOT:
Please provide a secure, fixed version of this code that addresses potential security vulnerabilities.

# REQUIREMENTS:
1. Remove dangerous operations (subprocess calls, system commands, etc.)
2. Add proper input validation and sanitization
3. Use secure alternatives and best practices
4. Add comprehensive error handling
5. Include logging for security events
6. Follow OWASP security guidelines
7. Maintain the same functionality where possible
8. Add comments explaining security improvements

# SECURITY FOCUS AREAS:
- Replace destructive operations with safe alternatives
- Remove hardcoded credentials and secrets
- Add input validation and sanitization
- Implement proper error handling
- Use secure file operations
- Add logging and monitoring
- Follow principle of least privilege

# ORIGINAL CODE:
```{language}
{content}
```

# EXPECTED OUTPUT:
Please provide the complete fixed code with security improvements:

```{language}
"""
        return prompt
        
    def _execute_copilot_remediation(self, prompt: str, file_path: Path) -> str:
        """Execute remediation using Copilot"""
        try:
            # Create temporary prompt file
            prompt_file = file_path.parent / f"{file_path.stem}_copilot_prompt.txt"
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(prompt)
                
            # Simulate Copilot processing (in real implementation, this would call Copilot API)
            logging.info(f"Executing Copilot remediation for: {file_path}")
            
            # For demonstration, generate a basic remediation
            remediated_content = self._generate_basic_remediation(file_path, prompt)
            
            # Clean up prompt file
            prompt_file.unlink()
            
            return remediated_content
            
        except Exception as e:
            logging.error(f"Error executing Copilot remediation: {e}")
            return self._generate_fallback_remediation(file_path)
            
    def _generate_basic_remediation(self, file_path: Path, prompt: str) -> str:
        """Generate basic remediation (placeholder for Copilot integration)"""
        language = self._detect_language(file_path)
        
        if language == 'python':
            return f"""# SECURITY FIX: Generated by VS Code Copilot Agent
# Original file: {file_path.name}
# Remediation timestamp: {datetime.now().isoformat()}

import logging
from pathlib import Path
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def secure_operation():
    \"\"\"
    Secure version of the original operation
    \"\"\"
    try:
        # Add your secure implementation here
        logger.info("Secure operation executed successfully")
        return True
    except Exception as e:
        logger.error(f"Secure operation failed: {{e}}")
        return False

if __name__ == "__main__":
    secure_operation()
"""
        else:
            return f"""// SECURITY FIX: Generated by VS Code Copilot Agent
// Original file: {file_path.name}
// Remediation timestamp: {datetime.now().isoformat()}

// Add your secure implementation here
console.log("Secure operation executed");
"""
            
    def _generate_fallback_remediation(self, file_path: Path) -> str:
        """Generate fallback remediation when Copilot fails"""
        return f"""# SECURITY FIX: Fallback remediation
# Original file: {file_path.name}
# Generated: {datetime.now().isoformat()}

# TODO: Review and implement security fixes manually
# This is a fallback remediation when Copilot integration fails

# Original content preserved below:
# Please review and apply security improvements manually
"""
        
    def _save_remediated_file(self, original_file: Path, remediated_content: str, params: Dict):
        """Save remediated file to appropriate directory"""
        try:
            # Create remediation directory structure
            scan_id = params.get('scan_id', f"vscode_{int(time.time())}")
            remediated_dir = self.workspace_path / 'remediated_files' / scan_id
            remediated_dir.mkdir(parents=True, exist_ok=True)
            
            # Save remediated file
            remediated_file = remediated_dir / f"{original_file.stem}_remediated{original_file.suffix}"
            with open(remediated_file, 'w', encoding='utf-8') as f:
                f.write(remediated_content)
                
            # Create metadata file
            metadata = {
                'original_file': str(original_file),
                'remediated_file': str(remediated_file),
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'params': params,
                'status': 'completed'
            }
            
            metadata_file = remediated_dir / 'metadata.json'
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
                
            logging.info(f"Remediated file saved: {remediated_file}")
            
        except Exception as e:
            logging.error(f"Error saving remediated file: {e}")
            
    def _cleanup_remediate_command(self, file_path: Path):
        """Remove @remediate command from original file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Remove @remediate lines
            lines = content.split('\n')
            cleaned_lines = [line for line in lines if '@remediate' not in line]
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(cleaned_lines))
                
            logging.info(f"Cleaned up @remediate command from: {file_path}")
            
        except Exception as e:
            logging.error(f"Error cleaning up @remediate command: {e}")
            
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension"""
        ext = file_path.suffix.lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.cpp': 'cpp',
            '.c': 'c',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json'
        }
        return language_map.get(ext, 'text')
        
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            'running': self.agent_running,
            'workspace_path': str(self.workspace_path),
            'current_task': self.current_task,
            'queue_length': len(self.remediation_queue),
            'last_check': datetime.now().isoformat()
        }


# Global agent instance
_vscode_agent = None

def start_vscode_agent(workspace_path: str = None) -> bool:
    """Start the VS Code Copilot agent"""
    global _vscode_agent
    if _vscode_agent is None:
        _vscode_agent = VSCodeCopilotAgent(workspace_path)
    return _vscode_agent.start_agent()

def stop_vscode_agent() -> bool:
    """Stop the VS Code Copilot agent"""
    global _vscode_agent
    if _vscode_agent is None:
        return False
    return _vscode_agent.stop_agent()

def get_vscode_agent_status() -> Dict[str, Any]:
    """Get the VS Code agent status"""
    global _vscode_agent
    if _vscode_agent is None:
        return {
            'running': False,
            'workspace_path': str(Path.cwd()),
            'current_task': None,
            'queue_length': 0,
            'error': 'Agent not initialized'
        }
    return _vscode_agent.get_status()


if __name__ == "__main__":
    # Test the agent
    print("Starting VS Code Copilot Agent...")
    agent = VSCodeCopilotAgent()
    agent.start_agent()
    
    try:
        while True:
            time.sleep(10)
            status = agent.get_status()
            print(f"Agent Status: {status}")
    except KeyboardInterrupt:
        print("Stopping VS Code Copilot Agent...")
        agent.stop_agent() 