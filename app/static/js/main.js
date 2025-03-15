document.addEventListener('DOMContentLoaded', function() {
    // Get form elements
    const emailForm = document.getElementById('emailForm');
    const uploadForm = document.getElementById('uploadForm');
    const resultsCard = document.getElementById('resultsCard');
    const loadingModal = new bootstrap.Modal(document.getElementById('loadingModal'));
    
    // Add event listener for email form submission
    emailForm.addEventListener('submit', function(e) {
        e.preventDefault();
        analyzeEmail();
    });
    
    // Add event listener for file upload form submission
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        uploadAndAnalyzeEmail();
    });
    
    // Function to analyze pasted email content
    function analyzeEmail() {
        const emailContent = document.getElementById('emailContent').value.trim();
        const senderEmail = document.getElementById('senderEmail').value.trim();
        const emailSubject = document.getElementById('emailSubject').value.trim();
        
        if (!emailContent) {
            alert('Please enter email content');
            return;
        }
        
        // Show loading modal
        loadingModal.show();
        
        // Prepare data for API request
        const data = {
            email_content: emailContent,
            sender_email: senderEmail,
            subject: emailSubject
        };
        
        // Send API request
        fetch('/api/analyze-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(result => {
            // Hide loading modal
            loadingModal.hide();
            
            // Display results
            displayResults(result);
        })
        .catch(error => {
            loadingModal.hide();
            console.error('Error:', error);
            alert('An error occurred while analyzing the email. Please try again.');
        });
    }
    
    // Function to upload and analyze email file
    function uploadAndAnalyzeEmail() {
        const fileInput = document.getElementById('emailFile');
        
        if (!fileInput.files || fileInput.files.length === 0) {
            alert('Please select a file to upload');
            return;
        }
        
        const file = fileInput.files[0];
        const reader = new FileReader();
        
        // Show loading modal
        loadingModal.show();
        
        reader.onload = function(e) {
            const fileContent = e.target.result;
            
            // Prepare data for API request
            const data = {
                email_content: fileContent
            };
            
            // Send API request
            fetch('/api/analyze-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(result => {
                // Hide loading modal
                loadingModal.hide();
                
                // Display results
                displayResults(result);
            })
            .catch(error => {
                loadingModal.hide();
                console.error('Error:', error);
                alert('An error occurred while analyzing the email. Please try again.');
            });
        };
        
        reader.onerror = function() {
            loadingModal.hide();
            alert('Error reading file');
        };
        
        reader.readAsText(file);
    }
    
    // Function to display analysis results
    function displayResults(result) {
        // Show results card
        resultsCard.style.display = 'block';
        
        // Scroll to results
        resultsCard.scrollIntoView({ behavior: 'smooth' });
        
        // Update risk score and level
        const riskScoreValue = document.getElementById('riskScoreValue');
        const riskLevelText = document.getElementById('riskLevelText');
        const riskSummary = document.getElementById('riskSummary');
        const riskScoreCircle = document.querySelector('.risk-score-circle');
        
        // Set risk score
        riskScoreValue.textContent = result.risk_score;
        
        // Set risk level and color
        riskLevelText.textContent = result.risk_level + ' Risk';
        
        // Remove previous classes
        riskScoreCircle.classList.remove('risk-score-low', 'risk-score-medium', 'risk-score-high');
        
        // Add appropriate class based on risk level
        if (result.risk_level === 'Low') {
            riskScoreCircle.classList.add('risk-score-low');
            riskSummary.classList.remove('alert-warning', 'alert-danger');
            riskSummary.classList.add('alert-success');
            riskSummary.innerHTML = '<strong>Low Risk:</strong> This email appears to be legitimate based on our analysis.';
        } else if (result.risk_level === 'Medium') {
            riskScoreCircle.classList.add('risk-score-medium');
            riskSummary.classList.remove('alert-success', 'alert-danger');
            riskSummary.classList.add('alert-warning');
            riskSummary.innerHTML = '<strong>Medium Risk:</strong> This email shows some suspicious characteristics. Review with caution.';
        } else {
            riskScoreCircle.classList.add('risk-score-high');
            riskSummary.classList.remove('alert-success', 'alert-warning');
            riskSummary.classList.add('alert-danger');
            riskSummary.innerHTML = '<strong>High Risk:</strong> This email shows strong indicators of being a phishing attempt.';
        }
        
        // Update analysis details
        updateAnalysisDetails(result.analysis_details);
    }
    
    // Function to update analysis details
    function updateAnalysisDetails(details) {
        // Update content analysis
        const contentAnalysisDetails = document.getElementById('contentAnalysisDetails');
        const contentFlags = details.content_analysis.flags;
        
        let contentHtml = `<p>Content Risk Score: ${Math.round(details.content_analysis.score * 100)}%</p>`;
        
        if (contentFlags && contentFlags.length > 0) {
            contentHtml += '<h6>Flags:</h6><ul>';
            contentFlags.forEach(flag => {
                contentHtml += `<li class="flag-item">${flag}</li>`;
            });
            contentHtml += '</ul>';
        } else {
            contentHtml += '<p>No content issues detected.</p>';
        }
        
        contentAnalysisDetails.innerHTML = contentHtml;
        
        // Update sender analysis
        const senderAnalysisDetails = document.getElementById('senderAnalysisDetails');
        const senderFlags = details.sender_analysis.flags;
        
        let senderHtml = `<p>Sender Risk Score: ${Math.round(details.sender_analysis.score * 100)}%</p>`;
        
        if (senderFlags && senderFlags.length > 0) {
            senderHtml += '<h6>Flags:</h6><ul>';
            senderFlags.forEach(flag => {
                senderHtml += `<li class="flag-item">${flag}</li>`;
            });
            senderHtml += '</ul>';
        } else {
            senderHtml += '<p>No sender issues detected.</p>';
        }
        
        senderAnalysisDetails.innerHTML = senderHtml;
        
        // Update URL analysis
        const urlAnalysisDetails = document.getElementById('urlAnalysisDetails');
        const urlFlags = details.url_analysis.flags;
        
        let urlHtml = `<p>URL Risk Score: ${Math.round(details.url_analysis.score * 100)}%</p>`;
        
        if (urlFlags && urlFlags.length > 0) {
            urlHtml += '<h6>Flags:</h6><ul>';
            urlFlags.forEach(flag => {
                urlHtml += `<li class="flag-item">${flag}</li>`;
            });
            urlHtml += '</ul>';
        } else {
            urlHtml += '<p>No URL issues detected or no URLs found in the email.</p>';
        }
        
        urlAnalysisDetails.innerHTML = urlHtml;
    }
});
