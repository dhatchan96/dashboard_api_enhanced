// Test script to check CORS issues
// Run this in the browser console

async function testCORS() {
  console.log('Testing CORS...');
  
  try {
    // Test basic endpoint
    const testResponse = await fetch('http://localhost:5000/api/test-cors');
    const testData = await testResponse.json();
    console.log('✅ Basic CORS test:', testData);
    
    // Test Copilot projects endpoint
    const projectsResponse = await fetch('http://localhost:5000/api/copilot/projects');
    const projectsData = await projectsResponse.json();
    console.log('✅ Copilot projects test:', projectsData);
    
    // Test available files endpoint (if you have a scan ID)
    const scanId = 'test_scan_id'; // Replace with actual scan ID
    const filesResponse = await fetch(`http://localhost:5000/api/copilot/files/${scanId}`);
    const filesData = await filesResponse.json();
    console.log('✅ Available files test:', filesData);
    
  } catch (error) {
    console.error('❌ CORS Error:', error);
    console.error('Error details:', error.message);
  }
}

// Run the test
testCORS(); 