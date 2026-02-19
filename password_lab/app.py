from flask import Flask, render_template, request, redirect, url_for, flash, session
from utils.auth_plaintext import register_user_plaintext, login_user_plaintext
from utils.auth_hashed import register_user_hashed, login_user_hashed
from utils.password_policy import validate_password, get_password_requirements
from utils.rate_limiter import (record_failed_login, reset_failed_logins, 
                                is_account_locked, get_lockout_message)
from utils.file_handler import initialize_users_file
import secrets

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)


AUTH_MODE = 'bcrypt' 

if AUTH_MODE == 'plaintext':
    print("\n" + "="*60)
    print(" WARNING: PLAINTEXT MODE ACTIVE (INSECURE)")
    print("="*60)
    print("This mode is for educational purposes ONLY!")
    print("NEVER use plaintext storage in production.")
    print("="*60 + "\n")
else:
    print(f"\nAuthentication Mode: {AUTH_MODE.upper()} (Secure)\n")


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
        
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('register.html', 
                                 auth_mode=AUTH_MODE,
                                 requirements=get_password_requirements())
        
        if AUTH_MODE == 'plaintext':
            success, message = register_user_plaintext(username, password)
        else: 
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

            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))
        else:
            record_failed_login(username)

            flash('Invalid username or password', 'error')
    
    return render_template('login.html', auth_mode=AUTH_MODE)


@app.route('/home')
def home():

    if 'username' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    
    return render_template('home.html', 
                         username=session['username'],
                         auth_mode=AUTH_MODE)


@app.route('/logout')
def logout():

    username = session.get('username', 'User')
    session.clear()
    flash(f'Logged out successfully. See you later, {username}!', 'info')
    return redirect(url_for('login'))



@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('login.html', auth_mode=AUTH_MODE), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    flash('An internal error occurred. Please try again.', 'error')
    return render_template('login.html', auth_mode=AUTH_MODE), 500


if __name__ == '__main__':
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
