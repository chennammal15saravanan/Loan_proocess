  const loanDropdown = document.getElementById('loanAmount');

  for (let amount = 10000; amount <= 200000; amount += 10000) {
    const option = document.createElement('option');
    option.value = amount;
    option.textContent = `₹${amount.toLocaleString('en-IN')}`;
    loanDropdown.appendChild(option);
  } 
 
 document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('welcome-dashboard').style.display = 'block';

    // Handle sidebar navigation
    document.querySelectorAll('.sidebar-submenu a').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const href = link.getAttribute('href').substring(1);
        document.querySelectorAll('.section').forEach(section => section.style.display = 'none');
        document.getElementById(href).style.display = 'block';
        if (href === 'view-request-loan') {
          fetchLoans();
        } else if (href === 'referral-loans') {
          fetchReferralLoans();
        } else if (href === 'product-desc') {
          fetchProducts();
        }
      });
    });

    // Fetch and Render Loans
    function fetchLoans() {
      fetch('/get-loans')
        .then(response => response.json())
        .then(data => {
          const loanTableBody = document.getElementById('loanTableBody');
          loanTableBody.innerHTML = '';
          data.loans.forEach(loan => {
            const row = document.createElement('tr');
            row.dataset.id = loan.id;
            row.innerHTML = `
              <td>${loan.id}</td>
              <td>${loan.first_name} ${loan.last_name}</td>
              <td>$${parseFloat(loan.loan_amount).toFixed(2)}</td>
              <td><span class="badge bg-${loan.status === 'pending' ? 'warning' : loan.status === 'accepted' ? 'success' : 'danger'}">${loan.status.charAt(0).toUpperCase() + loan.status.slice(1)}</span></td>
              <td><a href="${loan.aadhaar_url}" target="_blank">View Aadhaar</a></td>
              <td><a href="${loan.pan_url}" target="_blank">View PAN</a></td>
              <td>${loan.referred_by ? 'Merchant' : 'Direct'}</td>
            `;
            loanTableBody.appendChild(row);
          });
        })
        .catch(error => {
          console.error('Error fetching loans:', error);
          alert('Error fetching loan requests.');
        });
    }

    // Fetch and Render Referral Loans
    function fetchReferralLoans() {
  fetch('/get-referral-loans')
    .then(response => response.json())
    .then(data => {
      const referralLoanTableBody = document.getElementById('referralLoanTableBody');
      referralLoanTableBody.innerHTML = '';
      data.loans.forEach(loan => {
        const row = document.createElement('tr');
        row.dataset.id = loan.id;
        row.innerHTML = `
          <td>${loan.customer_name}</td>
          <td>₹${Number(loan.amount).toLocaleString('en-IN', { maximumFractionDigits: 0 })}</td>

          <td><span class="badge bg-${
            loan.status.toLowerCase() === 'pending' ? 'warning' :
            loan.status.toLowerCase() === 'accepted' ? 'success' : 'danger'
          }">${loan.status}</span></td>
          <td><button class="btn btn-info btn-sm viewDetails" data-id="${loan.id}">View Details</button></td>
        `;
        referralLoanTableBody.appendChild(row);
      });

      // Add event listeners for View Details buttons
      document.querySelectorAll('.viewDetails').forEach(button => {
        button.addEventListener('click', () => {
          const loanId = button.dataset.id;
          fetch(`/get-referral-loan-details/${loanId}`)
            .then(response => response.json())
            .then(data => {
              if (data.loan) {
                const loan = data.loan;
                document.getElementById('detailFirstName').textContent = loan.first_name || 'N/A';
                document.getElementById('detailLastName').textContent = loan.last_name || 'N/A';
                document.getElementById('detailDob').textContent = loan.dob || 'N/A';
                document.getElementById('detailPhone').textContent = loan.phone || 'N/A';
                document.getElementById('detailAddress').textContent = loan.address || 'N/A';
                document.getElementById('detailAadhaar').textContent = loan.aadhaar_number || 'N/A';
                document.getElementById('detailPan').textContent = loan.pan_number || 'N/A';
                document.getElementById('detailOccupation').textContent = loan.occupation || 'N/A';
                document.getElementById('detailAge').textContent = loan.age || 'N/A';
                document.getElementById('detailMonthlyIncome').textContent = `₹${loan.monthly_income.toFixed(2) || '0.00'}`;
                document.getElementById('detailLoanAmount').textContent = `₹${loan.loan_amount.toFixed(2) || '0.00'}`;
                document.getElementById('detailLoanPurpose').textContent = loan.loan_purpose || 'N/A';
                document.getElementById('detailStatus').textContent = loan.status || 'N/A';

                // Only set Aadhaar and PAN URL links
                const setUrlLink = (elementId, url) => {
                  const linkElement = document.getElementById(elementId);
                  if (url && url !== 'N/A') {
                    linkElement.href = url;
                    linkElement.style.display = 'inline';
                  } else {
                    linkElement.href = '#';
                    linkElement.style.display = 'none';
                  }
                };

                setUrlLink('detailAadhaarUrl', loan.aadhaar_url);
                setUrlLink('detailPanUrl', loan.pan_url);

                const status = loan.status.toLowerCase();
                const addDocumentsBtn = document.getElementById('addDocumentsBtn');
                const closeBtn = document.getElementById('loanDetailsCloseBtn');
                if (status === 'accepted') {
                  addDocumentsBtn.style.display = 'inline-block';
                  closeBtn.style.display = 'none';
                  addDocumentsBtn.dataset.loanId = loanId;
                } else {
                  addDocumentsBtn.style.display = 'none';
                  closeBtn.style.display = 'inline-block';
                }

                new bootstrap.Modal(document.getElementById('loanDetailsModal')).show();
              } else {
                alert('Error fetching loan details.');
              }
            })
            .catch(error => {
              console.error('Error fetching loan details:', error);
              alert('Error fetching loan details.');
            });
        });
      });
    })
    .catch(error => {
      console.error('Error fetching referral loans:', error);
      alert('Error fetching referral loans.');
    });
}

    document.querySelectorAll('#statusDropdown .dropdown-item').forEach(item => {
      item.addEventListener('click', () => {
        const status = item.getAttribute('data-status');
        const rows = document.querySelectorAll('#loanTableBody tr');
        rows.forEach(row => {
          const rowStatus = row.querySelector('td:nth-child(4) span').textContent.toLowerCase();
          row.style.display = status === 'all' || rowStatus === status ? '' : 'none';
        });
        document.getElementById('statusDropdown').textContent = status.charAt(0).toUpperCase() + status.slice(1);
      });
    });

    // Search and Status Filter for Referral Loans
    document.getElementById('referralLoanSearch').addEventListener('input', (e) => {
      const searchTerm = e.target.value.toLowerCase();
      const rows = document.querySelectorAll('#referralLoanTableBody tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
      });
    });

    document.querySelectorAll('#referralStatusDropdown .dropdown-item').forEach(item => {
      item.addEventListener('click', () => {
        const status = item.getAttribute('data-status');
        const rows = document.querySelectorAll('#referralLoanTableBody tr');
        rows.forEach(row => {
          const rowStatus = row.querySelector('td:nth-child(3) span').textContent.toLowerCase();
          row.style.display = status === 'all' || rowStatus === status ? '' : 'none';
        });
        document.getElementById('referralStatusDropdown').textContent = status.charAt(0).toUpperCase() + status.slice(1);
      });
    });

    // Add Referral Loan
    const referralLoanModal = new bootstrap.Modal(document.getElementById('referralLoanModal'));
    document.getElementById('addReferralLoanBtn').addEventListener('click', () => {
      document.getElementById('referralLoanForm').reset();
      referralLoanModal.show();
    });

    document.getElementById('referralLoanForm').addEventListener('submit', (e) => {
      e.preventDefault();
      const formData = new FormData();
      const fields = {
        first_name: document.getElementById('customerFirstName').value,
        last_name: document.getElementById('customerLastName').value,
        dob: document.getElementById('customerDob').value,
        phone: document.getElementById('customerPhone').value,
        address: document.getElementById('customerAddress').value,
        aadhaar_number: document.getElementById('customerAadhaarNumber').value,
        pan_number: document.getElementById('customerPanNumber').value,
        occupation: document.getElementById('customerOccupation').value,
        age: document.getElementById('customerAge').value,
        monthly_income: document.getElementById('customerMonthlyIncome').value,
        loan_amount: document.getElementById('loanAmount').value,
        loan_purpose: document.getElementById('loanPurpose').value,
        aadhaar_file: document.getElementById('aadhaarFile').files[0],
        pan_file: document.getElementById('panFile').files[0]
      };

      // Validate all fields
      for (let field in fields) {
        if (!fields[field] || (field.includes('file') && !fields[field])) {
          alert(`Please fill in the ${field.replace('_', ' ')} field.`);
          return;
        }
      }

      // Additional validation
      if (fields.aadhaar_number.length !== 12 || !/^\d+$/.test(fields.aadhaar_number)) {
        alert('Aadhaar number must be 12 digits.');
        return;
      }
      if (fields.pan_number.length !== 10 || !/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(fields.pan_number)) {
        alert('PAN number must be 10 characters in valid format (e.g., ABCDE1234F).');
        return;
      }
      if (isNaN(fields.age) || fields.age < 18) {
        alert('Age must be a number and at least 18.');
        return;
      }
      if (isNaN(fields.monthly_income) || fields.monthly_income < 0) {
        alert('Monthly income must be a non-negative number.');
        return;
      }
      if (isNaN(fields.loan_amount) || fields.loan_amount <= 0) {
        alert('Loan amount must be a positive number.');
        return;
      }

      formData.append('first_name', fields.first_name);
      formData.append('last_name', fields.last_name);
      formData.append('dob', fields.dob);
      formData.append('age', fields.age);
      formData.append('phone', fields.phone);
      formData.append('address', fields.address);
      formData.append('occupation', fields.occupation);
      formData.append('monthlyIncome', fields.monthly_income);
      formData.append('loanAmount', fields.loan_amount);
      formData.append('loanPurpose', fields.loan_purpose);
      formData.append('aadharNumber', fields.aadhaar_number);
      formData.append('panNumber', fields.pan_number);
      formData.append('aadharFile', fields.aadhaar_file);
      formData.append('panFile', fields.pan_file);

      fetch('/add-referral-loan', {
        method: 'POST',
        body: formData
      })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
        } else {
          alert(data.message);
          referralLoanModal.hide();
          document.getElementById('referralLoanForm').reset();
          fetchReferralLoans();
        }
      })
      .catch(error => {
        console.error('Error adding referral loan:', error);
        alert('Error adding referral loan.');
      });
    });

    // Product Management
    const productModal = new bootstrap.Modal(document.getElementById('productModal'));
    const productForm = document.getElementById('productForm');
    const productTableBody = document.getElementById('productTableBody');

    // Add Product Button
    document.getElementById('addProductBtn').addEventListener('click', () => {
      document.getElementById('productModalLabel').textContent = 'Add Product';
      document.getElementById('productForm').reset();
      document.getElementById('productId').value = '';
      productModal.show();
    });

    // Handle Form Submission
    productForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const productId = document.getElementById('productId').value;
      const productName = document.getElementById('productName').value;
      const productDescription = document.getElementById('productDescription').value;
      const productPrice = document.getElementById('productPrice').value;

      if (isNaN(productPrice) || productPrice <= 0) {
        alert('Price must be a valid positive number');
        return;
      }

      const formData = new FormData();
      formData.append('productName', productName);
      formData.append('productDescription', productDescription);
      formData.append('productPrice', productPrice);

      const url = productId ? `/update-product/${productId}` : '/add-product';
      const method = 'POST';

      fetch(url, {
        method: method,
        body: formData
      })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
        } else {
          alert(data.message);
          productModal.hide();
          productForm.reset();
          fetchProducts();
        }
      })
      .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
      });
    });

    // Handle Edit Product
    document.querySelectorAll('.editProduct').forEach(button => {
      button.addEventListener('click', () => {
        const productId = button.dataset.id;
        fetch(`/get-products`)
          .then(response => response.json())
          .then(data => {
            const product = data.products.find(p => p.product_id === productId);
            if (product) {
              document.getElementById('productModalLabel').textContent = 'Edit Product';
              document.getElementById('productId').value = product.product_id;
              document.getElementById('productName').value = product.name;
              document.getElementById('productDescription').value = product.description || '';
              document.getElementById('productPrice').value = product.price;
              productModal.show();
            } else {
              alert('Product not found');
            }
          })
          .catch(error => {
            console.error('Error fetching product:', error);
            alert('Error fetching product details.');
          });
      });
    });

    // Fetch and Render Products
    function fetchProducts() {
      fetch('/get-products')
        .then(response => response.json())
        .then(data => {
          productTableBody.innerHTML = '';
          data.products.forEach(product => {
            const row = document.createElement('tr');
            row.dataset.id = product.product_id;
            row.innerHTML = `
              <td>${product.name}</td>
              <td>${product.description || 'N/A'}</td>
              <td>₹${Number(product.price).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>

              <td>
                <button class="btn btn-warning btn-sm editProduct" data-id="${product.product_id}">Edit</button>
              </td>
            `;
            productTableBody.appendChild(row);

            // Reattach edit button event listeners
            row.querySelector('.editProduct').addEventListener('click', () => {
              document.getElementById('productModalLabel').textContent = 'Edit Product';
              document.getElementById('productId').value = product.product_id;
              document.getElementById('productName').value = product.name;
              document.getElementById('productDescription').value = product.description || '';
              document.getElementById('productPrice').value = product.price;
              productModal.show();
            });
          });
        })
        .catch(error => {
          console.error('Error fetching products:', error);
          alert('Error fetching products.');
        });
    }

    // Initial fetch of products when Product Description section is opened
    document.querySelector('a[href="#product-desc"]').addEventListener('click', () => {
      fetchProducts();
    });

    // Add Documents Modal
    const addDocumentsModal = new bootstrap.Modal(document.getElementById('addDocumentsModal'));
    document.getElementById('addDocumentsBtn').addEventListener('click', () => {
      const loanId = document.getElementById('addDocumentsBtn').dataset.loanId;
      document.getElementById('loanIdForDocuments').value = loanId;
      document.getElementById('addDocumentsForm').reset();
      addDocumentsModal.show();
    });

    document.getElementById('addDocumentsForm').addEventListener('submit', (e) => {
      e.preventDefault();
      const loanId = document.getElementById('loanIdForDocuments').value;
      const formData = new FormData();
      formData.append('loanId', loanId);

      const files = {
        appraisalSlip: document.getElementById('appraisalSlip').files[0],
        invoice: document.getElementById('invoice').files[0],
        goldPhoto: document.getElementById('goldPhoto').files[0],
        aadhaarFront: document.getElementById('aadhaarFront').files[0],
        aadhaarBack: document.getElementById('aadhaarBack').files[0],
        panFront: document.getElementById('panFront').files[0],
        panBack: document.getElementById('panBack').files[0],
        bankStatement: document.getElementById('bankStatement').files[0],
        incomeProof: document.getElementById('incomeProof').files[0],
        addressProof: document.getElementById('addressProof').files[0],
        utilityBill: document.getElementById('utilityBill').files[0]
      };

      for (let key in files) {
        if (files[key]) {
          formData.append(key, files[key]);
        }
      }

      fetch(`/add-loan-documents/${loanId}`, {
        method: 'POST',
        body: formData
      })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          alert(data.error);
        } else {
          alert(data.message);
          addDocumentsModal.hide();
          fetchReferralLoans(); // Refresh the loan list to reflect new documents
        }
      })
      .catch(error => {
        console.error('Error adding loan documents:', error);
        alert('Error adding loan documents.');
      });
    });
  });