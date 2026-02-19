"""
Password Security Lab - Main Flask Application
===============================================

SECURE CODING EXPERIMENT - PASSWORD STORAGE DEMONSTRATION
=========================================================

This application demonstrates the evolution from insecure to secure password storage:
- PHASE 1: Plaintext storage (insecure - for demonstration only)
- PHASE 2: Bcrypt hashing (secure - production-ready)
- PHASE 3: Salt uniqueness demonstration
- PHASE 4: Breach simulation (see breach_simulation.py)
- PHASE 5: Password policy enforcement
- PHASE 6: Rate limiting for brute-force protection
- PHASE 7: Secure error messages (no username enumeration)

To run this application:
1. Install dependencies: pip install -r requirements.txt
2. Run the app: python app.py
3. Open browser: http://localhost:5000

Default Configuration:
- Uses BCRYPT authentication (secure)
- To test plaintext mode, modify AUTH_MODE below
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
from utils.auth_plaintext import register_user_plaintext, login_user_plaintext
from utils.auth_hashed import register_user_hashed, login_user_hashed
from utils.password_policy import validate_password, get_password_requirements
from utils.rate_limiter import (record_failed_login, reset_failed_logins, 
                                is_account_locked, get_lockout_message)
from utils.file_handler import initialize_users_file
import secrets

app = Flask(__name__)

# Secret key for session management (in production, use environment variable)
app.secret_key = secrets.token_hex(16)

# ==================== CONFIGURATION ====================
# Change AUTH_MODE to switch between authentication methods
# Options: 'plaintext' (INSECURE) or 'bcrypt' (SECURE)
AUTH_MODE = 'bcrypt'  # ✅ Use secure mode by default

# Display warning if insecure mode is active
if AUTH_MODE == 'plaintext':
    print("\n" + "="*60)
    print("⚠️  WARNING: PLAINTEXT MODE ACTIVE (INSECURE)")
    print("="*60)
    print("This mode is for educational purposes ONLY!")
    print("NEVER use plaintext storage in production.")
    print("="*60 + "\n")
else:
    print(f"\n✅ Authentication Mode: {AUTH_MODE.upper()} (Secure)\n")

# ==================== ROUTES ====================

@app.route('/')
def index():
    """
    Home page - redirects to login or shows welcome message.
    """
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration page.
    
    GET: Display registration form
    POST: Process registration with password validation
    
    PHASE 5: Password policy is enforced here
    - Minimum length check
    - Common password rejection
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html', 
                                 auth_mode=AUTH_MODE,
                                 requirements=get_password_requirements())
        
        # PHASE 5: Validate password against policy
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('register.html', 
                                 auth_mode=AUTH_MODE,
                                 requirements=get_password_requirements())
        
        # Register user based on authentication mode
        if AUTH_MODE == 'plaintext':
            success, message = register_user_plaintext(username, password)
        else:  # bcrypt
            success, message = register_user_hashed(username, password)
        
        if success:
            flash(f'Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('register.html', 
                         auth_mode=AUTH_MODE,
                         requirements=get_password_requirements())


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login page.
    
    GET: Display login form
    POST: Process login with authentication
    
    PHASE 6: Rate limiting is enforced here
    - Tracks failed login attempts
    - Locks account after 5 failed attempts
    
    PHASE 7: Secure error messages
    - Never reveals if username exists
    - Always shows generic "Invalid username or password"
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html', auth_mode=AUTH_MODE)
        
        # PHASE 6: Check if account is locked (rate limiting)
        if is_account_locked(username):
            flash(get_lockout_message(), 'error')
            return render_template('login.html', auth_mode=AUTH_MODE)
        
        # Attempt authentication based on mode
        if AUTH_MODE == 'plaintext':
            success, message = login_user_plaintext(username, password)
        else:  # bcrypt
            success, message = login_user_hashed(username, password)
        
        if success:
            # PHASE 6: Reset failed login counter on success
            reset_failed_logins(username)
            
            # Create session
            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            # PHASE 6: Record failed login attempt
            record_failed_login(username)
            
            # PHASE 7: Generic error message (secure)
            # This prevents username enumeration - attacker can't tell if:
            # - Username doesn't exist
            # - Username exists but password is wrong
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', auth_mode=AUTH_MODE)


@app.route('/home')
def home():
    """
    Protected home page - only accessible after login.
    """
    if 'username' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    
    return render_template('home.html', 
                         username=session['username'],
                         auth_mode=AUTH_MODE)


@app.route('/logout')
def logout():
    """
    Log out user by clearing session.
    """
    username = session.get('username', 'User')
    session.clear()
    flash(f'Logged out successfully. See you later, {username}!', 'info')
    return redirect(url_for('login'))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('login.html', auth_mode=AUTH_MODE), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    flash('An internal error occurred. Please try again.', 'error')
    return render_template('login.html', auth_mode=AUTH_MODE), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize users file if it doesn't exist
    initialize_users_file()
    
    print("\n" + "="*60)
    print("PASSWORD SECURITY LAB - Flask Application")
    print("="*60)
    print(f"Authentication Mode: {AUTH_MODE.upper()}")
    print(f"Server: http://localhost:5000")
    print("\nAvailable routes:")
    print("  • /register - Create new account")
    print("  • /login - User login")
    print("  • /home - Protected page (requires login)")
    print("  • /logout - Log out")
    print("\nSecurity Features Active:")
    print("  ✅ Password policy enforcement (min 8 chars)")
    print("  ✅ Rate limiting (5 failed attempts → lockout)")
    print("  ✅ Secure error messages (no username enumeration)")
    if AUTH_MODE == 'bcrypt':
        print("  ✅ Bcrypt hashing with automatic salting")
    print("\nPress CTRL+C to stop the server")
    print("="*60 + "\n")
    
    # Run Flask development server
    app.run(debug=True, host='127.0.0.1', port=5000)
