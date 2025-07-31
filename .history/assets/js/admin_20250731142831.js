    let currentLoanId = null;

    document.addEventListener('DOMContentLoaded', () => {
      // Show the welcome dashboard and fetch loan stats by default
      document.getElementById('welcome-dashboard').style.display = 'block';
      fetchLoanApplications(); // Fetch loans to populate stats on load

      // Initialize charts for the dashboard
      initializeCharts();

      // Handle sidebar navigation
      document.querySelectorAll('.sidebar-submenu a').forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          const href = link.getAttribute('href').substring(1);
          document.querySelectorAll('.section').forEach(section => {
            section.style.display = 'none';
          });
          const targetSection = document.getElementById(href);
          if (targetSection) {
            targetSection.style.display = 'block';
            if (href === 'manage-loans') {
              fetchLoanApplications();
            } else if (href === 'accepted-loans') {
              fetchAcceptedLoans();
            }
          } else {
            console.error(`Section with ID ${href} not found`);
          }
        });
      });

      // Search filter for loan applications
      const loanSearchInput = document.getElementById('loanSearch');
      if (loanSearchInput) {
        loanSearchInput.addEventListener('input', () => {
          applyFilters();
        });
      } else {
        console.error('Loan search input not found');
      }

      // Search filter for accepted loans
      const acceptedLoanSearchInput = document.getElementById('acceptedLoanSearch');
      if (acceptedLoanSearchInput) {
        acceptedLoanSearchInput.addEventListener('input', (e) => {
          const searchTerm = e.target.value.toLowerCase();
          const rows = document.querySelectorAll('#acceptedLoanTableBody tr');
          rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm) ? '' : 'none';
          });
        });
      } else {
        console.error('Accepted loan search input not found');
      }

      // Status filter for loan applications
      let currentStatus = 'all';
      document.querySelectorAll('#statusDropdown .dropdown-item').forEach(item => {
        item.addEventListener('click', (e) => {
          e.preventDefault();
          currentStatus = item.getAttribute('data-status').toLowerCase();
          const statusDropdown = document.getElementById('statusDropdown');
          if (statusDropdown) {
            statusDropdown.textContent = currentStatus === 'all' ? 'Status' : 
              currentStatus.charAt(0).toUpperCase() + currentStatus.slice(1);
          }
          applyFilters();
          console.log(`Status filter applied: ${currentStatus}`);
        });
      });

      // Combined filter function for search and status
      function applyFilters() {
        const searchTerm = loanSearchInput.value.toLowerCase();
        const rows = document.querySelectorAll('#loanTableBody tr');
        let visibleRows = 0;
        rows.forEach(row => {
          const statusCell = row.querySelector('td:nth-child(4) span');
          if (!statusCell) {
            console.warn('Status cell not found for row:', row);
            row.style.display = 'none';
            return;
          }
          const rowStatus = statusCell.textContent.toLowerCase().trim();
          const text = row.textContent.toLowerCase();
          const statusMatch = currentStatus === 'all' || rowStatus === currentStatus;
          const searchMatch = searchTerm ? text.includes(searchTerm) : true;
          row.style.display = statusMatch && searchMatch ? '' : 'none';
          if (statusMatch && searchMatch) visibleRows++;
        });
        console.log(`Filtered rows - Status: ${currentStatus}, Search: "${searchTerm}", Visible: ${visibleRows}`);
      }
    });

    function initializeCharts() {
      // Total Loans Chart
      var totalLoansOptions = {
        chart: { type: 'line', height: 50, sparkline: { enabled: true } },
        series: [{ name: 'Total Loans', data: [0] }],
        stroke: { curve: 'smooth', width: 2 },
        colors: ['#3b5998'],
        tooltip: { enabled: false }
      };
      var totalLoansChart = new ApexCharts(document.querySelector("#total-loans-chart"), totalLoansOptions);
      totalLoansChart.render();

      // Pending Loans Chart
      var pendingLoansOptions = {
        chart: { type: 'line', height: 50, sparkline: { enabled: true } },
        series: [{ name: 'Pending Loans', data: [0] }],
        stroke: { curve: 'smooth', width: 2 },
        colors: ['#ff9900'],
        tooltip: { enabled: false }
      };
      var pendingLoansChart = new ApexCharts(document.querySelector("#pending-loans-chart"), pendingLoansOptions);
      pendingLoansChart.render();

      // Accepted Loans Chart
      var acceptedLoansOptions = {
        chart: { type: 'line', height: 50, sparkline: { enabled: true } },
        series: [{ name: 'Accepted Loans', data: [0] }],
        stroke: { curve: 'smooth', width: 2 },
        colors: ['#00cc00'],
        tooltip: { enabled: false }
      };
      var acceptedLoansChart = new ApexCharts(document.querySelector("#accepted-loans-chart"), acceptedLoansOptions);
      acceptedLoansChart.render();

      // Loan Purpose Pie Chart
      var loanPurposeOptions = {
        chart: {
          type: 'pie',
          height: 250
        },
        series: [0, 0, 0, 0, 0, 0], // Personal, Home, Educational, Medical, Vehicle, Business
        labels: ['Personal Loan', 'Home Loan', 'Educational Loan', 'Medical Loan', 'Vehicle Loan', 'Business Loan'],
        colors: ['#3b5998', '#00cc00', '#ff9900', '#dc3545', '#17a2b8', '#6f42c1'],
        dataLabels: {
          enabled: true,
          formatter: function (val) {
            return val.toFixed(1) + '%';
          }
        },
        legend: { show: false },
        plotOptions: {
          pie: {
            expandOnClick: false,
            dataLabels: {
              offset: 0,
              minAngleToShowLabel: 10
            }
          }
        },
        tooltip: {
          y: {
            formatter: function (val) {
              return val + ' applications';
            }
          }
        },
        responsive: [{
          breakpoint: 480,
          options: {
            chart: { height: 200 }
          }
        }]
      };
      var loanPurposePieChart = new ApexCharts(document.querySelector("#loanPurposePieChart"), loanPurposeOptions);
      loanPurposePieChart.render();

      // Store charts for dynamic updates
      window.loanCharts = {
        total: totalLoansChart,
        pending: pendingLoansChart,
        accepted: acceptedLoansChart,
        pie: loanPurposePieChart
      };
    }

    function updateLoanStats(loans) {
      const totalCount = loans.length;
      const pendingCount = loans.filter(loan => loan.status.toLowerCase() === 'pending').length;
      const acceptedCount = loans.filter(loan => loan.status.toLowerCase() === 'accepted').length;

      // Calculate loan purpose counts
      const loanPurposes = {
        'Personal Loan': 0,
        'Home Loan': 0,
        'Educational Loan': 0,
        'Medical Loan': 0,
        'Vehicle Loan': 0,
        'Business Loan': 0
      };
      loans.forEach(loan => {
        const purpose = loan.loan_purpose ? loan.loan_purpose.trim() : '';
        const normalizedPurpose = Object.keys(loanPurposes).find(
          key => key.toLowerCase() === purpose.toLowerCase()
        ) || purpose;
        if (loanPurposes.hasOwnProperty(normalizedPurpose)) {
          loanPurposes[normalizedPurpose]++;
        } else {
          console.warn(`Unknown loan purpose: ${purpose}`);
        }
      });

      // Update card counts
      document.getElementById('total-loans-count').textContent = totalCount.toLocaleString();
      document.getElementById('pending-loans-count').textContent = pendingCount.toLocaleString();
      document.getElementById('accepted-loans-count').textContent = acceptedCount.toLocaleString();

      // Update trends
      document.getElementById('total-loans-trend').innerHTML = totalCount > 0 ? 
        `Total: <span class="bg-success-focus px-1 rounded-2 fw-medium text-success-main text-sm">+${totalCount}</span> applications` : 
        'No change this week';
      document.getElementById('pending-loans-trend').innerHTML = pendingCount > 0 ? 
        `Pending: <span class="bg-warning-focus px-1 rounded-2 fw-medium text-warning-main text-sm">+${pendingCount}</span> applications` : 
        'No change this week';
      document.getElementById('accepted-loans-trend').innerHTML = acceptedCount > 0 ? 
        `Accepted: <span class="bg-success-focus px-1 rounded-2 fw-medium text-success-main text-sm">+${acceptedCount}</span> applications` : 
        'No change this week';

      // Update charts
      window.loanCharts.total.updateSeries([{ data: [totalCount] }]);
      window.loanCharts.pending.updateSeries([{ data: [pendingCount] }]);
      window.loanCharts.accepted.updateSeries([{ data: [acceptedCount] }]);
      window.loanCharts.pie.updateSeries([
        loanPurposes['Personal Loan'],
        loanPurposes['Home Loan'],
        loanPurposes['Educational Loan'],
        loanPurposes['Medical Loan'],
        loanPurposes['Vehicle Loan'],
        loanPurposes['Business Loan']
      ]);
    }

    function setCurrentLoanId(loanId) {
      currentLoanId = loanId;
      console.log("Current Loan ID set to:", currentLoanId);
    }

    function showToast(message, isError = false) {
      const toastId = isError ? 'errorToast' : 'successToast';
      const toast = new bootstrap.Toast(document.getElementById(toastId));
      document.querySelector(`#${toastId} .toast-body`).textContent = message;
      toast.show();
    }

    function confirmLoanStatus() {
      const confirmationText = document.getElementById("confirmationText").value.trim();
      const managerName = document.getElementById("managerName").value.trim();

      if (confirmationText.toLowerCase() !== "confirm loan") {
        showToast("Please type 'confirm loan' to proceed.", true);
        return;
      }

      if (!managerName) {
        showToast("Please enter your name.", true);
        return;
      }

      if (!currentLoanId) {
        showToast("Loan ID is missing. Please refresh and try again.", true);
        return;
      }

      fetch('/update-loan-status', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          loan_id: currentLoanId,
          status: 'accepted',
          manager_name: managerName
        })
      })
      .then(res => res.json())
      .then(data => {
        if (data.message) {
          showToast(data.message);
          const modal = bootstrap.Modal.getInstance(document.getElementById('confirmLoanModal'));
          if (modal) modal.hide();
          fetchLoanApplications(); // Refresh stats and table
          console.log("Loan applications table and stats refreshed after status update.");
        } else {
          showToast(data.error || "An error occurred.", true);
        }
      })
      .catch(err => {
        console.error("Error updating loan status:", err);
        showToast("Failed to update loan status due to a network or server error.", true);
      });
    }

    function fetchLoanApplications() {
  const loanTableBody = document.getElementById('loanTableBody');
  if (!loanTableBody) {
    console.error('Loan table body not found');
    return;
  }

  fetch('/get-loan-applications?_=' + new Date().getTime())
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      console.log("Fetched loan applications data:", data); // Log full response
      if (data.error) {
        throw new Error(data.error);
      }
      loanTableBody.innerHTML = '';
      if (!data.loans || data.loans.length === 0) {
        loanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No loan applications found.</td></tr>';
        updateLoanStats([]);
        return;
      }
      data.loans.forEach(loan => {
        console.log("Processing loan:", loan); // Log each loan object
        const row = document.createElement('tr');
        row.dataset.id = loan.request_id;
        const statusClass = loan.status.toLowerCase() === 'pending' ? 'bg-warning' :
                          loan.status.toLowerCase() === 'accepted' ? 'bg-success' : 'bg-danger';
        row.innerHTML = `
          <td>${loan.first_name}</td>
          <td>${loan.address || 'N/A'}</td>
          
          <td><span class="badge ${statusClass}">${loan.status}</span></td>
          <td>
            <button class="btn btn-primary btn-sm viewLoan" data-id="${loan.request_id}">View</button>
          </td>
        `;
        loanTableBody.appendChild(row);
        row.querySelector('.viewLoan').addEventListener('click', () => viewLoanDetails(loan.request_id));
      });
      updateLoanStats(data.loans); // Update dashboard stats and pie chart
    })
    .catch(error => {
      console.error('Error fetching loans:', error);
      loanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Error loading loan applications. Please try again later.</td></tr>';
      updateLoanStats([]);
    });
}

    function fetchAcceptedLoans() {
      const acceptedLoanTableBody = document.getElementById('acceptedLoanTableBody');
      if (!acceptedLoanTableBody) {
        console.error('Accepted loan table body not found');
        return;
      }

      fetch('/get-loan-applications?status=accepted&_=' + new Date().getTime())
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          console.log("Fetched accepted loans:", data);
          if (data.error) {
            throw new Error(data.error);
          }
          acceptedLoanTableBody.innerHTML = '';
          if (!data.loans || data.loans.length === 0) {
            acceptedLoanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No accepted loans found.</td></tr>';
            return;
          }
          data.loans.forEach(loan => {
            const row = document.createElement('tr');
            row.dataset.id = loan.request_id;
            row.innerHTML = `
              <td>${loan.first_name}</td>
              <td>${loan.address || 'N/A'}</td>
              <td>₹${parseFloat(loan.loan_amount || 0).toFixed(2)}</td>
              <td><span class="badge bg-success">${loan.status}</span></td>
              <td>
                <button class="btn btn-primary btn-sm viewLoan" data-id="${loan.request_id}">View</button>
              </td>
            `;
            acceptedLoanTableBody.appendChild(row);
            row.querySelector('.viewLoan').addEventListener('click', () => viewLoanDetails(loan.request_id));
          });
        })
        .catch(error => {
          console.error('Error fetching accepted loans:', error);
          acceptedLoanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Error loading accepted loans. Please try again later.</td></tr>';
        });
    }

   function viewLoanDetails(loanId) {
  fetch(`/get-loan-details/${loanId}`)
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (data.error) {
        throw new Error(data.error);
      }
      const loan = data.loan;
      const modalLoanDetails = document.querySelector('#confirmLoanModal #loanDetailsList');
      modalLoanDetails.innerHTML = `
        <li><strong>Customer Name:</strong> ${loan.first_name} ${loan.last_name || ''}</li>
        <li><strong>Loan Amount:</strong> ₹${parseFloat(loan.loan_amount || 0).toFixed(2)}</li>
        <li><strong>Loan Purpose:</strong> ${loan.loan_purpose || 'N/A'}</li>
        <li><strong>Monthly Income:</strong> ₹${parseFloat(loan.monthly_income || 0).toFixed(2)}</li>
        <li><strong>Application Date:</strong> ${loan.created_at || 'N/A'}</li>
      `;

      let leftColumn = `
        <div class="symmetric-col">
          <p><strong>First Name:</strong> ${loan.first_name || 'N/A'}</p>
          <p><strong>Last Name:</strong> ${loan.last_name || 'N/A'}</p>
          <p><strong>Date of Birth:</strong> ${loan.dob || 'N/A'}</p>
          <p><strong>Age:</strong> ${loan.age || 'N/A'}</p>
          <p><strong>Phone:</strong> ${loan.phone || 'N/A'}</p>
          <p><strong>Address:</strong> ${loan.address || 'N/A'}</p>
          <p><strong>Occupation:</strong> ${loan.occupation || 'N/A'}</p>
        </div> 
      `;
      let rightColumn = `
        <div class="symmetric-col">
          <p><strong>Loan Amount:</strong> ₹${parseFloat(loan.loan_amount || 0).toFixed(2)}</p>
          <p><strong>Loan Purpose:</strong> ${loan.loan_purpose || 'N/A'}</p>
          <p><strong>Aadhaar Number:</strong> ${loan.aadhaar_number || 'N/A'}</p>
          <p><strong>PAN Number:</strong> ${loan.pan_number || 'N/A'}</p>
          ${loan.status.toLowerCase() === 'accepted' ? `
            <p><strong>Aadhaar Document:</strong> <a href="${loan.aadhaar_url || '#'}" class="btn btn-pink" target="_blank">${loan.aadhaar_url ? 'View Document' : 'N/A'}</a></p>
            <p><strong>PAN Document:</strong> <a href="${loan.pan_url || '#'}" class="btn btn-pink" target="_blank">${loan.pan_url ? 'View Document' : 'N/A'}</a></p>
          ` : `
            <p><strong>Aadhaar Document:</strong> <a href="${loan.aadhaar_url || '#'}" class="text-primary text-decoration-underline" target="_blank">${loan.aadhaar_url ? 'View Document' : 'N/A'}</a></p>
            <p><strong>PAN Document:</strong> <a href="${loan.pan_url || '#'}" class="text-primary text-decoration-underline" target="_blank">${loan.pan_url ? 'View Document' : 'N/A'}</a></p>
          `}
        </div>
      `;
      let merchantDetails = `
        <div class="symmetric-col mt-4">
          <h6 class="fw-semibold mb-3">Merchant Details</h6>
          <p><strong>Referred By:</strong> ${loan.referred_by || 'N/A'}</p>
          <p><strong>Review Status:</strong> ${loan.review_status || 'N/A'}</p>
          <p><button type="button" class="btn btn-pink">Review Document</button></p>
        </div>
      `;

      const modal = document.createElement('div');
      modal.className = 'modal fade';
      modal.id = 'loanDetailsModal';
      modal.innerHTML = `
        <div class="modal-dialog modal-lg">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title">Loan Application Details</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
              <div class="row g-3">
                <div class="col-md-6">
                  ${leftColumn}
                </div>
                <div class="col-md-6">
                  ${rightColumn}
                </div>
                <div class="col-12">
                  ${merchantDetails}
                </div>
              </div>
            </div>
            <div class="modal-footer d-flex justify-content-between">
              <div>
                ${loan.status.toLowerCase() === 'pending' ?
                  `<button type="button" class="btn btn-success me-2" data-bs-toggle="modal" data-bs-target="#confirmLoanModal" onclick="setCurrentLoanId('${loanId}')">Accept</button>
                   <button type="button" class="btn btn-danger me-2" onclick="handleLoanDecision('${loanId}', 'rejected')">Reject</button>` :
                  ''}
              </div>
              <div>
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                ${loan.status.toLowerCase() !== 'accepted' && parseFloat(loan.loan_amount || 0) > 0 ?
                  `<button type="button" class="btn btn-primary" onclick="printLoanDetails('${loanId}')">Print</button>` :
                  ''}
              </div>
            </div>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
      const bsModal = new bootstrap.Modal(modal);
      bsModal.show();
      modal.addEventListener('hidden.bs.modal', () => {
        modal.remove();
      });
    })
    .catch(error => {
      console.error('Error fetching loan details:', error);
      showToast(`Error fetching loan details: ${error.message}. Please try again.`, true);
    });
}
    function handleLoanDecision(loanId, status) {
      fetch('/update-loan-status', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          loan_id: loanId,
          status: status
        })
      })
      .then(res => res.json())
      .then(data => {
        if (data.message) {
          showToast(data.message);
          const modal = bootstrap.Modal.getInstance(document.getElementById('loanDetailsModal'));
          if (modal) modal.hide();
          fetchLoanApplications(); // Refresh stats and table
        } else {
          showToast(data.error || "An error occurred.", true);
        }
      })
      .catch(err => {
        console.error("Error updating loan status:", err);
        showToast("Failed to update loan status due to a network or server error.", true);
      });
    }

    function printLoanDetails(loanId) {
      fetch(`/get-loan-details/${loanId}`)
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          if (data.error) {
            throw new Error(data.error);
          }
          const loan = data.loan;
          const { jsPDF } = window.jspdf;
          const doc = new jsPDF();

          const logo = new Image();
          logo.src = 'assets/images/logo.png';
          logo.onload = function() {
            doc.addImage(logo, 'PNG', 10, 10, 50, 20);
            doc.setFontSize(20);
            doc.text('Loan Application Details', 10, 40);
            doc.setFontSize(12);
            doc.text(`Loan ID: ${loan.request_id}`, 10, 50);
            doc.text(`Date: ${new Date().toLocaleDateString()}`, 10, 60);
            doc.setFontSize(16);
            doc.text('Borrower Details', 10, 80);
            doc.autoTable({
              startY: 90,
              head: [['Field', 'Value']],
              body: [
                ['First Name', loan.first_name || 'N/A'],
                ['Last Name', loan.last_name || 'N/A'],
                ['Date of Birth', loan.dob || 'N/A'],
                ['Age', loan.age || 'N/A'],
                ['Phone', loan.phone || 'N/A'],
                ['Address', loan.address || 'N/A'],
                ['Occupation', loan.occupation || 'N/A'],
                ['Monthly Income', `₹${parseFloat(loan.monthly_income || 0).toFixed(2)}`],
                ['Loan Amount', `₹${parseFloat(loan.loan_amount || 0).toFixed(2)}`],
                ['Loan Purpose', loan.loan_purpose || 'N/A'],
                ['Aadhaar Number', loan.aadhaar_number || 'N/A'],
                ['PAN Number', loan.pan_number || 'N/A'],
                ['Status', loan.status || 'N/A'],
                ['Application Date', loan.created_at || 'N/A'],
                ['Review Status', loan.review_status || 'N/A'],
              ],
              theme: 'striped',
              styles: { fontSize: 10 },
              headStyles: { fillColor: [0, 102, 204] },
            });
            let finalY = doc.lastAutoTable.finalY + 10;
            doc.setFontSize(16);
            doc.text('Merchant Details', 10, finalY);
            doc.autoTable({
              startY: finalY + 10,
              head: [['Field', 'Value']],
              body: [
                ['Referred By', loan.referred_by || 'N/A'],
              ],
              theme: 'striped',
              styles: { fontSize: 10 },
              headStyles: { fillColor: [0, 102, 204] },
            });
            finalY = doc.lastAutoTable.finalY + 20;
            doc.setFontSize(10);
            doc.text('Thank you for your business!', 10, finalY);
            doc.text('NBFC Admin Dashboard', 10, finalY + 10);
            doc.text('4517 Washington Ave. Manchester, Kentucky 39495', 10, finalY + 20);
            doc.text('random@gmail.com, +1 543 2198', 10, finalY + 30);
            doc.save(`Loan_Application_${loan.request_id}.pdf`);
          };
          logo.onerror = function() {
            console.error('Failed to load logo image');
            showToast('Failed to load logo for PDF. Generating PDF without logo.', true);
            doc.setFontSize(20);
            doc.text('Loan Application Details', 10, 40);
            doc.setFontSize(12);
            doc.text(`Loan ID: ${loan.request_id}`, 10, 50);
            doc.text(`Date: ${new Date().toLocaleDateString()}`, 10, 60);
            doc.setFontSize(16);
            doc.text('Borrower Details', 10, 80);
            doc.autoTable({
              startY: 90,
              head: [['Field', 'Value']],
              body: [
                ['First Name', loan.first_name || 'N/A'],
                ['Last Name', loan.last_name || 'N/A'],
                ['Date of Birth', loan.dob || 'N/A'],
                ['Age', loan.age || 'N/A'],
                ['Phone', loan.phone || 'N/A'],
                ['Address', loan.address || 'N/A'],
                ['Occupation', loan.occupation || 'N/A'],
                ['Monthly Income', `₹${parseFloat(loan.monthly_income || 0).toFixed(2)}`],
                ['Loan Amount', `₹${parseFloat(loan.loan_amount || 0).toFixed(2)}`],
                ['Loan Purpose', loan.loan_purpose || 'N/A'],
                ['Aadhaar Number', loan.aadhaar_number || 'N/A'],
                ['PAN Number', loan.pan_number || 'N/A'],
                ['Status', loan.status || 'N/A'],
                ['Application Date', loan.created_at || 'N/A'],
                ['Review Status', loan.review_status || 'N/A'],
              ],
              theme: 'striped',
              styles: { fontSize: 10 },
              headStyles: { fillColor: [0, 102, 204] },
            });
            let finalY = doc.lastAutoTable.finalY + 10;
            doc.setFontSize(16);
            doc.text('Merchant Details', 10, finalY);
            doc.autoTable({
              startY: finalY + 10,
              head: [['Field', 'Value']],
              body: [
                ['Referred By', loan.referred_by || 'N/A'],
              ],
              theme: 'striped',
              styles: { fontSize: 10 },
              headStyles: { fillColor: [0, 102, 204] },
            });
            finalY = doc.lastAutoTable.finalY + 20;
            doc.setFontSize(10);
            doc.text('Thank you for your business!', 10, finalY);
            doc.text('NBFC Admin Dashboard', 10, finalY + 10);
            doc.text('4517 Washington Ave. Manchester, Kentucky 39495', 10, finalY + 20);
            doc.text('random@gmail.com, +1 543 2198', 10, finalY + 30);
            doc.save(`Loan_Application_${loan.request_id}.pdf`);
          };
        })
        .catch(error => {
          console.error('Error fetching loan details for printing:', error);
          showToast(`Error fetching loan details for printing: ${error.message}.`, true);
        });
    }

    function printInvoice() {
      if (!currentLoanId) {
        showToast('Please select a loan to print.', true);
        return;
      }
      printLoanDetails(currentLoanId);
    }