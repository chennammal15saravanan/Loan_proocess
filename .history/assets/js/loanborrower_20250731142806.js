  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('welcome-dashboard').style.display = 'block';

    // Client-side validation for Aadhar and PAN
    document.getElementById('aadharNumber').addEventListener('input', (e) => {
      const aadharRegex = /^\d{12}$/;
      if (!aadharRegex.test(e.target.value)) {
        e.target.setCustomValidity('Aadhar number must be a 12-digit number.');
      } else {
        e.target.setCustomValidity('');
      }
    });

    document.getElementById('panNumber').addEventListener('input', (e) => {
      const panRegex = /^[A-Z]{5}\d{4}[A-Z]{1}$/;
      if (!panRegex.test(e.target.value)) {
        e.target.setCustomValidity('PAN number must be in the format ABCDE1234F.');
      } else {
        e.target.setCustomValidity('');
      }
    });

    // Client-side file size validation
    document.getElementById('aadharFile').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file && file.size > 5 * 1024 * 1024) {
        alert('Aadhar file size must be less than 5MB.');
        e.target.value = '';
      }
    });
    document.getElementById('panFile').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file && file.size > 5 * 1024 * 1024) {
        alert('PAN file size must be less than 5MB.');
        e.target.value = '';
      }
    });

    // Handle sidebar navigation
    document.querySelectorAll('.sidebar-submenu a').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const href = link.getAttribute('href').substring(1);
        document.querySelectorAll('.section').forEach(section => section.style.display = 'none');
        const section = document.getElementById(href);
        if (section) {
          section.style.display = 'block';
          if (href === 'view-loan') {
            fetchLoans();
          } else if (href === 'view-products') {
            fetchProducts();
          }
        }
      });
    });

    // Handle View Products button click
    document.getElementById('viewProductsBtn').addEventListener('click', () => {
      document.querySelectorAll('.section').forEach(sec => sec.style.display = 'none');
      const viewProductsSection = document.getElementById('view-products');
      if (viewProductsSection) {
        viewProductsSection.style.display = 'block';
        fetchProducts();
      }
    });

    // Handle Loan Form Submission
    const loanForm = document.getElementById('loanForm');
    const loanModal = new bootstrap.Modal(document.getElementById('loanModal'));

    if (loanForm) {
      loanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = new FormData(loanForm);

        fetch('/add-loan', {
          method: 'POST',
          body: formData
        })
        .then(response => {
          if (response.status === 401) {
            alert('Please sign in to continue.');
            window.location.href = '/sign-in';
            return;
          }
          return response.json();
        })
        .then(data => {
          if (data && data.error) {
            alert(data.error);
          } else if (data) {
            loanModal.hide();
            loanForm.reset();
            const successMessage = document.createElement('div');
            successMessage.className = 'alert alert-success alert-dismissible fade show';
            successMessage.innerHTML = `
              Loan application submitted successfully!
              <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            document.getElementById('apply-loan').prepend(successMessage);
          }
        })
        .catch(error => {
          console.error('Error:', error);
          alert('An error occurred while submitting the loan application.');
        });
      });
    }

    // Fetch and Render Loans
    function fetchLoans() {
      const loanTableBody = document.getElementById('loanTableBody');
      if (!loanTableBody) {
        console.warn('loanTableBody element not found');
        return;
      }

      fetch('/get-user-loans')
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          loanTableBody.innerHTML = '';
          if (data.loans && data.loans.length > 0) {
            data.loans.forEach(loan => {
              const row = document.createElement('tr');
              row.innerHTML = `
                <td>${loan.loan_id || 'N/A'}</td>
                
                <td>${loan.purpose || 'N/A'}</td>
                <td><span class="badge bg-${
                  loan.status.toLowerCase() === 'pending' ? 'warning' :
                  loan.status.toLowerCase() === 'accepted' ? 'success' : 'danger'
                }">${loan.status || 'N/A'}</span></td>
              `;
              loanTableBody.appendChild(row);
            });
          } else {
            loanTableBody.innerHTML = '<tr><td colspan="4">No loans found.</td></tr>';
          }
        })
        .catch(error => {
          console.error('Error fetching loans:', error);
          loanTableBody.innerHTML = '<tr><td colspan="4">Failed to load loans.</td></tr>';
        });
    }

    // Fetch and Render Products
    function fetchProducts() {
      const productTableBody = document.getElementById('productTableBody');
      if (!productTableBody) {
        console.warn('productTableBody element not found');
        return;
      }

      fetch('/get-all-products')
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          return response.json();
        })
        .then(data => {
          productTableBody.innerHTML = '';
          if (data.products && data.products.length > 0) {
            data.products.forEach(product => {
              const row = document.createElement('tr');
              row.innerHTML = `
                <td>${product.name || 'N/A'}</td>
                <td>${product.description || 'N/A'}</td>
                <td>₹${parseFloat(product.price || 0).toFixed(2)}</td>
                <td>${product.merchant_name || 'N/A'}</td>
              `;
              productTableBody.appendChild(row);
            });
          } else {
            productTableBody.innerHTML = '<tr><td colspan="4">No products found.</td></tr>';
          }
        })
        .catch(error => {
          console.error('Error fetching products:', error);
          productTableBody.innerHTML = '<tr><td colspan="4">Failed to load products.</td></tr>';
        });
    }

    // Optional: Live Search for Products
    const productSearch = document.getElementById('productSearch');
    if (productSearch) {
      productSearch.addEventListener('input', function () {
        const filter = this.value.toLowerCase();
        const rows = document.querySelectorAll('#productTableBody tr');
        rows.forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(filter) ? '' : 'none';
        });
      });
    }
  });