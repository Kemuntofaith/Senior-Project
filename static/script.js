// backtoschool_app/static/script.js
document.addEventListener('DOMContentLoaded', function() {
    // Cart quantity adjustments
    document.querySelectorAll('.quantity-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const input = this.parentElement.querySelector('.quantity-input');
            let value = parseInt(input.value);
            
            if (this.classList.contains('minus') && value > 1) {
                input.value = value - 1;
            } else if (this.classList.contains('plus')) {
                input.value = value + 1;
            }
            
            // Update cart via AJAX would go here
        });
    });

    // Theme color application
    const style = document.createElement('style');
    style.innerHTML = `
        .btn-primary {
            background-color: #89CFF0 !important;
        }
        .btn-secondary {
            background-color: #B5EAD7 !important;
        }
        .btn-accent {
            background-color: #FFD1DC !important;
        }
        .flash-success {
            background-color: #B5EAD7;
        }
        .flash-error {
            background-color: #FFD1DC;
        }
    `;
    document.head.appendChild(style);
});