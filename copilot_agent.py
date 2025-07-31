#!/usr/bin/env python3
"""
VS Code GitHub Copilot Extension Integration for Code Remediation
Generates prompts and instructions for use with VS Code Copilot extension
"""

import os
import json
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [VSCODE-COPILOT] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vscode_copilot_agent.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class VSCodeCopilotIntegration:
    """VS Code GitHub Copilot Extension integration for code generation"""
    
    def __init__(self):
        self.extension_available = self._check_vscode_extension()
        
    def _check_vscode_extension(self) -> bool:
        """Check if VS Code GitHub Copilot extension is available"""
        try:
            # In a real implementation, this would check for VS Code extension
            # For now, we'll assume it's available
            logging.info("VS Code GitHub Copilot extension integration ready")
            return True
        except Exception as e:
            logging.error(f"VS Code Copilot extension not available: {e}")
            return False
    
    def generate_copilot_prompt(self, original_code: str, issue_description: str, language: str, file_path: str) -> str:
        """
        Generate a prompt for VS Code GitHub Copilot extension
        This prompt can be copied and pasted into VS Code with Copilot enabled
        """
        prompt = f"""# SECURITY VULNERABILITY FIX REQUEST
# File: {file_path}
# Language: {language}

# ISSUE DESCRIPTION:
{issue_description}

# ORIGINAL VULNERABLE CODE:
```{language}
{original_code}
```

# TASK FOR GITHUB COPILOT:
Please provide a secure, fixed version of this code that addresses the security vulnerability.

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

# EXPECTED OUTPUT:
Please provide the complete fixed code with security improvements:

```{language}
"""
        return prompt
    
    def generate_vscode_instructions(self, scan_id: str, file_path: str, issues: List[Dict]) -> str:
        """Generate VS Code instructions for manual remediation"""
        instructions = f"""# VS CODE GITHUB COPILOT REMEDIATION INSTRUCTIONS
# Scan ID: {scan_id}
# File: {file_path}

## STEPS TO REMEDIATE:

1. **Open the file in VS Code:**
   - Open VS Code
   - Open the file: {file_path}
   - Ensure GitHub Copilot extension is enabled

2. **Copy the prompt below and paste it at the end of the file:**

{self.generate_copilot_prompt("", "", "python", file_path)}

3. **Use GitHub Copilot to generate fixes:**
   - Place cursor after the prompt
   - Press Ctrl+Enter (or Cmd+Enter on Mac) to trigger Copilot
   - Select the generated secure code
   - Replace the vulnerable code with the secure version

4. **Review and test the fixes:**
   - Review the generated code for security improvements
   - Test the functionality to ensure it works correctly
   - Verify that security vulnerabilities are addressed

## DETECTED ISSUES:
"""
        
        for i, issue in enumerate(issues, 1):
            instructions += f"""
{i}. **{issue.get('type', 'Unknown')}** - {issue.get('severity', 'Unknown')}
   - Message: {issue.get('message', 'No description')}
   - Code: {issue.get('code_snippet', 'No code snippet')}
   - Suggested Fix: {issue.get('suggested_fix', 'No suggestion')}
"""
        
        instructions += """
## SECURITY BEST PRACTICES TO FOLLOW:
- Use environment variables for secrets
- Validate and sanitize all inputs
- Use safe file operations
- Add proper error handling
- Implement logging for security events
- Follow principle of least privilege
- Use secure coding patterns

## AFTER REMEDIATION:
1. Save the file
2. Test the functionality
3. Review the changes
4. Commit the secure version
"""
        
        return instructions
    
    def create_remediation_workspace(self, scan_id: str, task_data: Dict) -> str:
        """Create a VS Code workspace for remediation"""
        workspace_dir = Path('vscode_remediation_workspaces') / scan_id
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Create VS Code workspace file
        workspace_file = workspace_dir / f'{scan_id}.code-workspace'
        
        workspace_config = {
            "folders": [
                {
                    "name": f"Remediation Workspace - {scan_id}",
                    "path": "."
                }
            ],
            "settings": {
                "github.copilot.enable": True,
                "github.copilot.enableAutoCompletions": True,
                "editor.suggest.showKeywords": True,
                "editor.suggest.showSnippets": True,
                "editor.suggest.showClasses": True,
                "editor.suggest.showFunctions": True,
                "editor.suggest.showVariables": True,
                "editor.suggest.showConstants": True,
                "editor.suggest.showEnums": True,
                "editor.suggest.showEnumMembers": True,
                "editor.suggest.showWords": True,
                "editor.suggest.showColors": True,
                "editor.suggest.showFiles": True,
                "editor.suggest.showReferences": True,
                "editor.suggest.showCustomcolors": True,
                "editor.suggest.showFolders": True,
                "editor.suggest.showTypeParameters": True,
                "editor.suggest.showUnits": True,
                "editor.suggest.showValues": True,
                "editor.suggest.showEnums": True,
                "editor.suggest.showEnumMembers": True,
                "editor.suggest.showKeywords": True,
                "editor.suggest.showWords": True,
                "editor.suggest.showColors": True,
                "editor.suggest.showFiles": True,
                "editor.suggest.showReferences": True,
                "editor.suggest.showCustomcolors": True,
                "editor.suggest.showFolders": True,
                "editor.suggest.showTypeParameters": True,
                "editor.suggest.showUnits": True,
                "editor.suggest.showValues": True
            },
            "extensions": {
                "recommendations": [
                    "GitHub.copilot",
                    "GitHub.copilot-chat",
                    "ms-python.python",
                    "ms-vscode.vscode-typescript-next",
                    "ms-vscode.vscode-json"
                ]
            }
        }
        
        with open(workspace_file, 'w', encoding='utf-8') as f:
            json.dump(workspace_config, f, indent=2)
        
        return str(workspace_file)


class CopilotAgent:
    """VS Code Copilot agent for code remediation"""
    
    def __init__(self, base_directory: str = "uploaded_projects"):
        self.base_directory = Path(base_directory)
        self.running = False
        self.thread = None
        self.poll_interval = 10  # seconds
        self.processed_tasks_count = 0
        self.vscode_copilot = VSCodeCopilotIntegration()
        
    def start(self) -> bool:
        """Start the Copilot agent"""
        if self.running:
            logging.warning("VS Code Copilot agent is already running")
            return False
            
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logging.info("VS Code Copilot agent started successfully")
        return True
    
    def stop(self) -> bool:
        """Stop the Copilot agent"""
        if not self.running:
            logging.warning("VS Code Copilot agent is not running")
            return False
            
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("VS Code Copilot agent stopped successfully")
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'processed_tasks_count': self.processed_tasks_count,
            'base_directory': str(self.base_directory),
            'last_check': datetime.now().isoformat(),
            'vscode_extension_available': self.vscode_copilot.extension_available,
            'integration_type': 'VS Code GitHub Copilot Extension'
        }
    
    def _run(self):
        """Main agent loop"""
        logging.info("VS Code Copilot agent main loop started")
        
        while self.running:
            try:
                self._discover_and_process_tasks()
                time.sleep(self.poll_interval)
            except Exception as e:
                logging.error(f"Error in VS Code Copilot agent loop: {e}")
                time.sleep(self.poll_interval)
    
    def _discover_and_process_tasks(self):
        """Discover and process pending Copilot tasks"""
        try:
            # Look for copilot_task.json files
            for task_file in self.base_directory.rglob("copilot_tasks/copilot_task.json"):
                try:
                    with open(task_file, 'r', encoding='utf-8') as f:
                        task_data = json.load(f)
                    
                    if task_data.get('status') == 'pending':
                        logging.info(f"Processing VS Code Copilot task: {task_file.parent.parent.name}")
                        self._process_task(task_file.parent.parent.name)
                        
                except Exception as e:
                    logging.error(f"Error reading task file {task_file}: {e}")
                    
        except Exception as e:
            logging.error(f"Error discovering tasks: {e}")
    
    def _process_task(self, scan_id: str):
        """Process a specific VS Code Copilot task"""
        try:
            task_file = self.base_directory / scan_id / 'copilot_tasks' / 'copilot_task.json'
            
            # Update status to processing
            with open(task_file, 'r', encoding='utf-8') as f:
                task_data = json.load(f)
            
            task_data['status'] = 'processing'
            task_data['processing_started'] = datetime.now().isoformat()
            
            with open(task_file, 'w', encoding='utf-8') as f:
                json.dump(task_data, f, indent=2)
            
            # Generate VS Code Copilot instructions
            result = self._generate_vscode_instructions(scan_id, task_data)
            
            # Update status
            task_data['status'] = 'completed'
            task_data['processing_completed'] = datetime.now().isoformat()
            task_data['result'] = result
            task_data['remediation_method'] = 'VS Code GitHub Copilot Extension'
            
            with open(task_file, 'w', encoding='utf-8') as f:
                json.dump(task_data, f, indent=2)
            
            self.processed_tasks_count += 1
            logging.info(f"VS Code Copilot task {scan_id} processed successfully")
            
        except Exception as e:
            logging.error(f"Error processing VS Code Copilot task {scan_id}: {e}")
            # Update status to error
            try:
                with open(task_file, 'r', encoding='utf-8') as f:
                    task_data = json.load(f)
                task_data['status'] = 'error'
                task_data['error'] = str(e)
                with open(task_file, 'w', encoding='utf-8') as f:
                    json.dump(task_data, f, indent=2)
            except:
                pass
    
    def _generate_vscode_instructions(self, scan_id: str, task_data: Dict) -> Dict:
        """Generate VS Code Copilot instructions for remediation"""
        try:
            original_dir = self.base_directory / scan_id / 'original'
            instructions_dir = self.base_directory / scan_id / 'vscode_instructions'
            instructions_dir.mkdir(parents=True, exist_ok=True)
            
            suggested_remediations = task_data.get('suggested_remediations', {})
            results = []
            
            # Create VS Code workspace
            workspace_file = self.vscode_copilot.create_remediation_workspace(scan_id, task_data)
            
            for file_path, remediations in suggested_remediations.items():
                try:
                    original_file = original_dir / file_path
                    if not original_file.exists():
                        logging.warning(f"Original file not found: {original_file}")
                        continue
                    
                    # Read original content
                    with open(original_file, 'r', encoding='utf-8') as f:
                        original_content = f.read()
                    
                    # Generate VS Code Copilot instructions
                    instructions = self.vscode_copilot.generate_vscode_instructions(
                        scan_id, file_path, remediations
                    )
                    
                    # Generate Copilot prompt
                    language = self._detect_language(file_path)
                    issue_description = self._create_issue_description(remediations)
                    copilot_prompt = self.vscode_copilot.generate_copilot_prompt(
                        original_content, issue_description, language, file_path
                    )
                    
                    # Save instructions
                    instruction_file = instructions_dir / f'{Path(file_path).stem}_instructions.md'
                    with open(instruction_file, 'w', encoding='utf-8') as f:
                        f.write(instructions)
                    
                    # Save Copilot prompt
                    prompt_file = instructions_dir / f'{Path(file_path).stem}_copilot_prompt.txt'
                    with open(prompt_file, 'w', encoding='utf-8') as f:
                        f.write(copilot_prompt)
                    
                    results.append({
                        'file': file_path,
                        'status': 'success',
                        'instructions_file': str(instruction_file),
                        'prompt_file': str(prompt_file),
                        'issues_count': len(remediations),
                        'language': language
                    })
                    
                    logging.info(f"Generated VS Code Copilot instructions for: {file_path}")
                    
                except Exception as e:
                    logging.error(f"Error generating instructions for file {file_path}: {e}")
                    results.append({
                        'file': file_path,
                        'status': 'error',
                        'error': str(e)
                    })
            
            return {
                'success': True,
                'files_processed': len(results),
                'files_successful': len([r for r in results if r['status'] == 'success']),
                'files_failed': len([r for r in results if r['status'] == 'error']),
                'workspace_file': workspace_file,
                'instructions_directory': str(instructions_dir),
                'results': results
            }
            
        except Exception as e:
            logging.error(f"Error in VS Code instruction generation: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
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
    
    def _create_issue_description(self, remediations: List[Dict]) -> str:
        """Create a comprehensive issue description from remediations"""
        if not remediations:
            return "General security improvements needed"
        
        descriptions = []
        for remediation in remediations:
            desc = f"- {remediation.get('message', 'Security issue')} "
            desc += f"(Severity: {remediation.get('severity', 'Unknown')})"
            if remediation.get('suggested_fix'):
                desc += f" - {remediation['suggested_fix']}"
            descriptions.append(desc)
        
        return "Security issues detected:\n" + "\n".join(descriptions)


# Global agent instance
_agent = None

def start_copilot_agent() -> bool:
    """Start the global VS Code Copilot agent"""
    global _agent
    if _agent is None:
        _agent = CopilotAgent()
    return _agent.start()

def stop_copilot_agent() -> bool:
    """Stop the global VS Code Copilot agent"""
    global _agent
    if _agent is None:
        return False
    return _agent.stop()

def get_agent_status() -> Dict[str, Any]:
    """Get the global agent status"""
    global _agent
    if _agent is None:
        return {
            'running': False,
            'poll_interval': 10,
            'processed_tasks_count': 0,
            'base_directory': 'uploaded_projects',
            'vscode_extension_available': True,
            'integration_type': 'VS Code GitHub Copilot Extension',
            'error': 'Agent not initialized'
        }
    return _agent.get_status()

if __name__ == "__main__":
    # Test the agent
    agent = CopilotAgent()
    print("Starting VS Code Copilot agent...")
    agent.start()
    
    try:
        while True:
            time.sleep(5)
            status = agent.get_status()
            print(f"Status: {status}")
    except KeyboardInterrupt:
        print("Stopping VS Code Copilot agent...")
        agent.stop() 