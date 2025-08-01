(function ($) {
  'use strict';

  // Sidebar submenu collapsible js
  $(".sidebar-menu .dropdown").on("click", function(){
    var item = $(this);
    item.siblings(".dropdown").children(".sidebar-submenu").slideUp();
    item.siblings(".dropdown").removeClass("dropdown-open");
    item.siblings(".dropdown").removeClass("open");
    item.children(".sidebar-submenu").slideToggle();
    item.toggleClass("dropdown-open");
  });

  $(".sidebar-toggle").on("click", function(){
    $(this).toggleClass("active");
    $(".sidebar").toggleClass("active");
    $(".dashboard-main").toggleClass("active");
  });

  $(".sidebar-mobile-toggle").on("click", function(){
    $(".sidebar").addClass("sidebar-open");
    $("body").addClass("overlay-active");
  });

  $(".sidebar-close-btn").on("click", function(){
    $(".sidebar").removeClass("sidebar-open");
    $("body").removeClass("overlay-active");
  });

  // To keep the current page active
  $(function () {
    for (
      var nk = window.location,
        o = $("ul#sidebar-menu a")
          .filter(function () {
            return this.href == nk;
          })
          .addClass("active-page")
          .parent()
          .addClass("active-page");
      ;
    ) {
      if (!o.is("li")) break;
      o = o.parent().addClass("show").parent().addClass("open");
    }
  });

  // Theme toggle functionality
  function calculateSettingAsThemeString({ localStorageTheme }) {
    if (localStorageTheme !== null) {
      return localStorageTheme;
    }
    return "light";
  }

  function updateButton({ buttonEl, isDark }) {
    const newCta = isDark ? "dark" : "light";
    buttonEl.setAttribute("aria-label", newCta);
    buttonEl.innerText = newCta;
  }

  function updateThemeOnHtmlEl({ theme }) {
    document.querySelector("html").setAttribute("data-theme", theme);
  }

  const button = document.querySelector("[data-theme-toggle]");
  const localStorageTheme = localStorage.getItem("theme");
  let currentThemeSetting = calculateSettingAsThemeString({ localStorageTheme });

  if (button) {
    updateButton({ buttonEl: button, isDark: currentThemeSetting === "dark" });
    updateThemeOnHtmlEl({ theme: currentThemeSetting });

    button.addEventListener("click", (event) => {
      const newTheme = currentThemeSetting === "dark" ? "light" : "dark";
      localStorage.setItem("theme", newTheme);
      updateButton({ buttonEl: button, isDark: newTheme === "dark" });
      updateThemeOnHtmlEl({ theme: newTheme });
      currentThemeSetting = newTheme;
    });
  } else {
    updateThemeOnHtmlEl({ theme: currentThemeSetting });
  }

  // Table header checkbox select all
  $('#selectAll').on('change', function () {
    $('.form-check .form-check-input').prop('checked', $(this).prop('checked')); 
  });

  // Remove table row when clicking remove button
  $('.remove-btn').on('click', function () {
    $(this).closest('tr').remove();
    if ($('.table tbody tr').length === 0) {
      $('.table').addClass('bg-danger');
      $('.no-items-found').show();
    }
  });

  // Existing loan dashboard functionality
  let currentLoanId = null;

  document.addEventListener('DOMContentLoaded', () => {
    // Show the welcome dashboard by default
    document.getElementById('welcome-dashboard').style.display = 'block';

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
      loanSearchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#loanTableBody tr');
        rows.forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(searchTerm) ? '' : 'none';
        });
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
    document.querySelectorAll('#statusDropdown .dropdown-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const status = item.getAttribute('data-status');
        const rows = document.querySelectorAll('#loanTableBody tr');
        rows.forEach(row => {
          const rowStatus = row.querySelector('td:nth-child(4) span').textContent.toLowerCase();
          row.style.display = status === 'all' || rowStatus === status ? '' : 'none';
        });
        const statusDropdown = document.getElementById('statusDropdown');
        if (statusDropdown) {
          statusDropdown.textContent = status === 'all' ? 'Status' : status.charAt(0).toUpperCase() + status.slice(1);
        }
      });
    });
  });

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

    $.ajax({
      url: '/update-loan-status',
      type: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      data: $.param({
        loan_id: currentLoanId,
        status: 'accepted',
        manager_name: managerName
      }),
      success: function(data) {
        if (data.message) {
          showToast(data.message);
          const modal = bootstrap.Modal.getInstance(document.getElementById('confirmLoanModal'));
          if (modal) modal.hide();
          fetchLoanApplications();
          console.log("Loan applications table refreshed after status update.");
        } else {
          showToast(data.error || "An error occurred.", true);
        }
      },
      error: function(err) {
        console.error("Error updating loan status:", err);
        showToast("Failed to update loan status due to a network or server error.", true);
      }
    });
  }

  function fetchLoanApplications() {
    const loanTableBody = document.getElementById('loanTableBody');
    if (!loanTableBody) {
      console.error('Loan table body not found');
      return;
    }

    $.ajax({
      url: '/get-loan-applications?_=' + new Date().getTime(),
      type: 'GET',
      success: function(data) {
        console.log("Fetched loan applications:", data);
        if (data.error) {
          throw new Error(data.error);
        }
        loanTableBody.innerHTML = '';
        if (!data.loans || data.loans.length === 0) {
          loanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No loan applications found.</td></tr>';
          return;
        }
        data.loans.forEach(loan => {
          const row = document.createElement('tr');
          row.dataset.id = loan.request_id;
          const statusClass = loan.status.toLowerCase() === 'pending' ? 'bg-warning' :
                              loan.status.toLowerCase() === 'accepted' ? 'bg-success' : 'bg-danger';
          row.innerHTML = `
            <td>${loan.first_name}</td>
            <td>${loan.address || 'N/A'}</td>
            <td>₹${Number(loan.amount).toLocaleString('en-IN', { maximumFractionDigits: 0 })}</td>
            <td><span class="badge ${statusClass}">${loan.status}</span></td>
            <td>
              <button class="btn btn-primary btn-sm viewLoan" data-id="${loan.request_id}">View</button>
            </td>
          `;
          loanTableBody.appendChild(row);

          row.querySelector('.viewLoan').addEventListener('click', () => viewLoanDetails(loan.request_id));
        });
      },
      error: function(error) {
        console.error('Error fetching loans:', error);
        loanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Error loading loan applications. Please try again later.</td></tr>';
      }
    });
  }

  function fetchAcceptedLoans() {
    const acceptedLoanTableBody = document.getElementById('acceptedLoanTableBody');
    if (!acceptedLoanTableBody) {
      console.error('Accepted loan table body not found');
      return;
    }

    $.ajax({
      url: '/get-loan-applications?status=accepted&_=' + new Date().getTime(),
      type: 'GET',
      success: function(data) {
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
            <td>₹${parseFloat(loan.amount || 0).toFixed(2)}</td>
            <td><span class="badge bg-success">${loan.status}</span></td>
            <td>
              <button class="btn btn-primary btn-sm viewLoan" data-id="${loan.request_id}">View</button>
            </td>
          `;
          acceptedLoanTableBody.appendChild(row);

          row.querySelector('.viewLoan').addEventListener('click', () => viewLoanDetails(loan.request_id));
        });
      },
      error: function(error) {
        console.error('Error fetching accepted loans:', error);
        acceptedLoanTableBody.innerHTML = '<tr><td colspan="5" class="text-center">Error loading accepted loans. Please try again later.</td></tr>';
      }
    });
  }

  function viewLoanDetails(loanId) {
    $.ajax({
      url: `/get-loan-details/${loanId}`,
      type: 'GET',
      success: function(data) {
        if (data.error) {
          throw new Error(data.error);
        }
        const loan = data.loan;
        const modalLoanDetails = document.querySelector('#confirmLoanModal #loanDetailsList');
        modalLoanDetails.innerHTML = `
          <li><strong>Customer Name:</strong> ${loan.first_name} ${loan.last_name || ''}</li>
          <li><strong>Loan Amount:</strong> $${parseFloat(loan.loan_amount || 0).toFixed(2)}</li>
          <li><strong>Loan Purpose:</strong> ${loan.loan_purpose || 'N/A'}</li>
          <li><strong>Monthly Income:</strong> $${parseFloat(loan.monthly_income || 0).toFixed(2)}</li>
          <li><strong>Application Date:</strong> ${loan.created_at || 'N/A'}</li>
        `;
        let modalContent = `
          <h6 class="fw-semibold mb-3">Borrower Details</h6>
          <p><strong>First Name:</strong> ${loan.first_name || 'N/A'}</p>
          <p><strong>Last Name:</strong> ${loan.last_name || 'N/A'}</p>
          <p><strong>Date of Birth:</strong> ${loan.dob || 'N/A'}</p>
          <p><strong>Age:</strong> ${loan.age || 'N/A'}</p>
          <p><strong>Phone:</strong> ${loan.phone || 'N/A'}</p>
          <p><strong>Address:</strong> ${loan.address || 'N/A'}</p>
          <p><strong>Occupation:</strong> ${loan.occupation || 'N/A'}</p>
          <p><strong>Monthly Income:</strong> $${parseFloat(loan.monthly_income || 0).toFixed(2)}</p>
          <p><strong>Loan Amount:</strong> $${parseFloat(loan.loan_amount || 0).toFixed(2)}</p>
          <p><strong>Loan Purpose:</strong> ${loan.loan_purpose || 'N/A'}</p>
          <p><strong>Aadhaar Number:</strong> ${loan.aadhaar_number || 'N/A'}</p>
          <p><strong>PAN Number:</strong> ${loan.pan_number || 'N/A'}</p>
          <p><strong>Aadhaar Document:</strong> <a href="${loan.aadhaar_url || '#'}" class="text-primary text-decoration-underline" target="_blank">${loan.aadhaar_url ? 'View Document' : 'N/A'}</a></p>
          <p><strong>PAN Document:</strong> <a href="${loan.pan_url || '#'}" class="text-primary text-decoration-underline" target="_blank">${loan.pan_url ? 'View Document' : 'N/A'}</a></p>
          <p><strong>Status:</strong> ${loan.status || 'N/A'}</p>
          <p><strong>Application Date:</strong> ${loan.created_at || 'N/A'}</p>
          <p><strong>Review Status:</strong> ${loan.review_status || 'N/A'}</p>
          <h6 class="fw-semibold mt-4 mb-3">Merchant Details</h6>
          <p><strong>Referred By:</strong> ${loan.referred_by || 'N/A'}</p>
        `;
        Object.keys(loan).forEach(key => {
          if (!['request_id', 'first_name', 'last_name', 'dob', 'age', 'phone', 'address', 'occupation', 'monthly_income', 'loan_amount', 'loan_purpose', 'aadhaar_number', 'pan_number', 'aadhaar_url', 'pan_url', 'status', 'created_at', 'review_status', 'referred_by'].includes(key)) {
            modalContent += `<p><strong>${key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}:</strong> ${loan[key] || 'N/A'}</p>`;
          }
        });
        const acceptButton = loan.status.toLowerCase() === 'pending' ? 
          `<button type="button" class="btn btn-success" data-bs-toggle="modal" data-bs-target="#confirmLoanModal" onclick="setCurrentLoanId('${loanId}')">Accept</button>` : 
          `<button type="button" class="btn btn-success" disabled>Accept</button>`;
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
                ${modalContent}
              </div>
              <div class="modal-footer">
                ${acceptButton}
                <button type="button" class="btn btn-danger" onclick="handleLoanDecision('${loanId}', 'rejected')">Reject</button>
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
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
      },
      error: function(error) {
        console.error('Error fetching loan details:', error);
        showToast(`Error fetching loan details: ${error.message}. Please try again.`, true);
      }
    });
  }

  function handleLoanDecision(loanId, status) {
    $.ajax({
      url: '/update-loan-status',
      type: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      data: $.param({
        loan_id: loanId,
        status: status
      }),
      success: function(data) {
        if (data.message) {
          showToast(data.message);
          const modal = bootstrap.Modal.getInstance(document.getElementById('loanDetailsModal'));
          if (modal) modal.hide();
          fetchLoanApplications();
        } else {
          showToast(data.error || "An error occurred.", true);
        }
      },
      error: function(err) {
        console.error("Error updating loan status:", err);
        showToast("Failed to update loan status due to a network or server error.", true);
      }
    });
  }

  function printInvoice() {
    // Determine which section is currently visible
    const manageLoansSection = document.getElementById('manage-loans');
    const acceptedLoansSection = document.getElementById('accepted-loans');
    let tableBody, tableTitle;

    if (manageLoansSection.style.display === 'block') {
      tableBody = document.getElementById('loanTableBody');
      tableTitle = 'Loan Applications';
    } else if (acceptedLoansSection.style.display === 'block') {
      tableBody = document.getElementById('acceptedLoanTableBody');
      tableTitle = 'Accepted Loans';
    } else {
      showToast('No table is currently visible to print.', true);
      return;
    }

    if (!tableBody || tableBody.children.length === 0) {
      showToast('No data available to print.', true);
      return;
    }

    // Extract table data
    const rows = tableBody.querySelectorAll('tr');
    const tableData = [];
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length >= 4) { // Ensure there are enough cells
        tableData.push([
          cells[0].textContent, // Name
          cells[1].textContent, // Address
          cells[2].textContent, // Amount
          cells[3].querySelector('span').textContent // Status
        ]);
      }
    });

    // Create PDF using jsPDF and jspdf-autotable
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    // Add title
    doc.setFontSize(18);
    doc.text(tableTitle, 14, 20);

    // Add table to PDF
    doc.autoTable({
      head: [['Name', 'Address', 'Amount', 'Status']],
      body: tableData,
      startY: 30,
      theme: 'grid',
      headStyles: { fillColor: [22, 160, 133] }, // Green header
      styles: { fontSize: 10 }
    });

    // Add footer with current date and time
    const currentDateTime = 'July 28, 2025, 01:18 PM IST';
    doc.setFontSize(10);
    doc.text(`Generated on: ${currentDateTime}`, 14, doc.internal.pageSize.height - 10);

    // Save the PDF
    doc.save(`${tableTitle.replace(/\s+/g, '_')}_2025-07-28_1318.pdf`);
  }
})(jQuery);