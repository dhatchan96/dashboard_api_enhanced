// Test script to demonstrate the Copilot Prompts feature
// This shows how the new "Prompts" button works in the UI

console.log('🚀 Testing Copilot Prompts Feature');
console.log('=' * 50);

// Mock data structure for copilot prompts
const mockCopilotPrompts = {
  "id_2is2zre55": [
    {
      file_name: "comprehensive_malware_tests.py",
      file_path: "test_files/comprehensive_malware_tests.py",
      prompt_text: `# Security Remediation Prompt for comprehensive_malware_tests.py

## File Information
- File: comprehensive_malware_tests.py
- Path: test_files/comprehensive_malware_tests.py
- Issues Found: 23

## Security Issues to Fix

### Issue 1: CRITICAL_BOMB - DESTRUCTIVE_PAYLOAD
- **Line**: 234
- **Message**: Detects potentially destructive operations that could be payloads of logic bombs
- **Code Snippet**: 
\`\`\`
subprocess.call(['rm', '-rf', '/var/log/*'])
\`\`\`
- **Suggested Fix**: CRITICAL: Remove destructive operations: subprocess.call(['rm', '-rf', '/var/log/*'])... Implement proper data management.
- **Threat Level**: EXTREME
- **Effort**: 120 minutes

### Issue 2: CRITICAL_BOMB - DESTRUCTIVE_PAYLOAD
- **Line**: 237
- **Message**: Detects potentially destructive operations that could be payloads of logic bombs
- **Code Snippet**: 
\`\`\`
os.remove('/home/user/.bash_history')
\`\`\`
- **Suggested Fix**: CRITICAL: Remove destructive operations: os.remove('/home/user/.bash_history')... Implement proper data management.
- **Threat Level**: EXTREME
- **Effort**: 120 minutes

## Instructions
Please review the code and apply the suggested fixes to address the security vulnerabilities. Focus on removing dangerous operations and implementing secure alternatives.

## Expected Output
Provide the remediated code with all security issues fixed. Include comments explaining what was changed and why.`,
      issues_count: 23,
      severity: "CRITICAL"
    },
    {
      file_name: "financial_fraud_tests.py",
      file_path: "test_files/financial_fraud_tests.py",
      prompt_text: `# Security Remediation Prompt for financial_fraud_tests.py

## File Information
- File: financial_fraud_tests.py
- Path: test_files/financial_fraud_tests.py
- Issues Found: 14

## Security Issues to Fix

### Issue 1: CRITICAL_BOMB - FINANCIAL_FRAUD
- **Line**: 11
- **Message**: Detects potential financial fraud and unauthorized money redirection
- **Code Snippet**: 
\`\`\`
# FRAUD: Redirect payments over $1000 to developer account
\`\`\`
- **Suggested Fix**: URGENT: Remove financial redirections: # FRAUD: Redirect payments over $1000 to developer... Use legitimate payment systems.
- **Threat Level**: EXTREME
- **Effort**: 90 minutes

### Issue 2: CRITICAL_BOMB - FINANCIAL_FRAUD
- **Line**: 76
- **Message**: Detects potential financial fraud and unauthorized money redirection
- **Code Snippet**: 
\`\`\`
transfer_crypto(amount, developer_wallet)
\`\`\`
- **Suggested Fix**: URGENT: Remove financial redirections: transfer_crypto(amount, developer_wallet)... Use legitimate payment systems.
- **Threat Level**: EXTREME
- **Effort**: 90 minutes

## Instructions
Please review the code and apply the suggested fixes to address the security vulnerabilities. Focus on removing dangerous operations and implementing secure alternatives.

## Expected Output
Provide the remediated code with all security issues fixed. Include comments explaining what was changed and why.`,
      issues_count: 14,
      severity: "CRITICAL"
    }
  ]
};

// Function to simulate the UI behavior
function simulateCopilotPromptsFeature() {
  console.log('📋 Simulating Copilot Prompts Feature');
  console.log('=' * 40);
  
  Object.entries(mockCopilotPrompts).forEach(([scanId, prompts]) => {
    console.log(`\n🔍 Scan ID: ${scanId}`);
    console.log(`📁 Total Files with Issues: ${prompts.length}`);
    
    prompts.forEach((prompt, index) => {
      console.log(`\n📄 File ${index + 1}: ${prompt.file_name}`);
      console.log(`📍 Path: ${prompt.file_path}`);
      console.log(`⚠️  Issues: ${prompt.issues_count}`);
      console.log(`🚨 Severity: ${prompt.severity}`);
      console.log(`📝 Prompt Length: ${prompt.prompt_text.length} characters`);
      
      // Show a preview of the prompt
      const preview = prompt.prompt_text.substring(0, 200) + '...';
      console.log(`📋 Preview: ${preview}`);
    });
  });
  
  console.log('\n✅ Feature Simulation Complete!');
  console.log('\n🎯 Key Features:');
  console.log('1. ✅ "Prompts" button shows all copilot prompts');
  console.log('2. ✅ Each prompt is formatted for easy copy-paste');
  console.log('3. ✅ Includes file information and security issues');
  console.log('4. ✅ Copy buttons for easy clipboard access');
  console.log('5. ✅ Responsive design for mobile devices');
}

// Function to demonstrate the copy functionality
function demonstrateCopyFeature() {
  console.log('\n📋 Demonstrating Copy Feature');
  console.log('=' * 30);
  
  const samplePrompt = mockCopilotPrompts["id_2is2zre55"][0];
  
  console.log('📄 Sample prompt for copying:');
  console.log('File:', samplePrompt.file_name);
  console.log('Issues:', samplePrompt.issues_count);
  console.log('Severity:', samplePrompt.severity);
  
  // Simulate copy to clipboard
  console.log('\n📋 Copying prompt to clipboard...');
  console.log('✅ Prompt copied successfully!');
  console.log('📋 Users can now paste this into their AI assistant or IDE');
}

// Run the simulation
simulateCopilotPromptsFeature();
demonstrateCopyFeature();

console.log('\n🎉 Copilot Prompts Feature Test Complete!');
console.log('\n📋 Summary:');
console.log('- Users can click "Prompts" button to see all copilot prompts');
console.log('- Each prompt is formatted with file info, issues, and instructions');
console.log('- Copy buttons allow easy copying to clipboard');
console.log('- Prompts are ready to paste into AI assistants or IDEs');
console.log('- Responsive design works on all devices'); 