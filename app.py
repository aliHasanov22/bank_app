#!/usr/bin/python3
import sqlite3
import random
import re
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
from flask import send_file

app = Flask(__name__)
app.secret_key = "ultimate_banking_v6_secret"
app.permanent_session_lifetime = timedelta(minutes=15)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False

# --- CONFIGURATION (V7) ---
DB_NAME = "atm_ultimate_web_v3.db"  # Using V3 to support new tables
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
TRANSFER_PENDING_THRESHOLD = 2000.0

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- DATABASE SETUP ---
def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Users (Updated with profile_pic for V7)
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        account_id TEXT PRIMARY KEY, name TEXT, pin TEXT, email TEXT, phone TEXT, 
        id_card TEXT UNIQUE, profile_pic TEXT DEFAULT 'default.png',
        status TEXT DEFAULT 'PENDING'
    )''')
    
    # 2. Chat Messages (New in V7)
    cursor.execute('''CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT, sender TEXT, 
        message TEXT, timestamp TEXT, is_read INTEGER DEFAULT 0
    )''')

    # 3. Balances
    cursor.execute('''CREATE TABLE IF NOT EXISTS balances (
        account_id TEXT, currency TEXT, amount REAL,
        PRIMARY KEY(account_id, currency), FOREIGN KEY(account_id) REFERENCES users(account_id)
    )''')
    
    # 4. Transactions
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT, timestamp TEXT,
        type TEXT, currency TEXT, amount REAL, note TEXT,
        status TEXT DEFAULT 'COMPLETED'
    )''')
    
    # 5. Cards
    cursor.execute('''CREATE TABLE IF NOT EXISTS cards (
        card_number TEXT PRIMARY KEY, account_id TEXT, cvc TEXT, status TEXT,
        expiry TEXT, card_type TEXT, currency TEXT, card_pin TEXT,
        card_name TEXT DEFAULT 'My Card', expense_limit REAL DEFAULT 5000.0,
        FOREIGN KEY(account_id) REFERENCES users(account_id)
    )''')

    # 5.1 Card Balances (Per-card ledger)
    cursor.execute('''CREATE TABLE IF NOT EXISTS card_balances (
        card_number TEXT PRIMARY KEY,
        amount REAL DEFAULT 0,
        FOREIGN KEY(card_number) REFERENCES cards(card_number)
    )''')
    
    # 6. Bonuses
    cursor.execute('''CREATE TABLE IF NOT EXISTS bonuses (
        account_id TEXT, currency TEXT, balance REAL DEFAULT 0,
        earned_this_month REAL DEFAULT 0, last_month_str TEXT,
        PRIMARY KEY(account_id, currency)
    )''')
    
    # 7. Tickets
    cursor.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT, issue TEXT,
        status TEXT DEFAULT 'OPEN', timestamp TEXT,
        FOREIGN KEY(account_id) REFERENCES users(account_id)
    )''')

    # 8. Admin Logs
    cursor.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id TEXT,
        action TEXT,
        target TEXT,
        timestamp TEXT
    )''')

    # NEW: Term Deposits Table
    cursor.execute('''CREATE TABLE IF NOT EXISTS term_deposits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id TEXT,
        amount REAL,
        currency TEXT,
        term_months INTEGER,
        interest_rate REAL,
        is_monthly_payout INTEGER,
        start_date TEXT,
        end_date TEXT,
        last_payout_date TEXT,
        payout_card_number TEXT,
        status TEXT DEFAULT 'ACTIVE', -- ACTIVE, COMPLETED, CLOSED
        projected_profit REAL
    )''')
    
    conn.commit()
    conn.close()

def check_and_update_db_schema():
    """Helper to ensure users have a status column for suspension."""
    conn = get_db()
    try:
        # Try to select the column to see if it exists
        conn.execute("SELECT status FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # If error, column missing -> Add it
        print("Migrating DB: Adding 'status' column to users table...")
        conn.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'PENDING'")
        conn.commit()

    try:
        conn.execute("SELECT status FROM transactions LIMIT 1")
    except sqlite3.OperationalError:
        print("Migrating DB: Adding 'status' column to transactions table...")
        conn.execute("ALTER TABLE transactions ADD COLUMN status TEXT DEFAULT 'COMPLETED'")
        conn.commit()

    conn.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id TEXT,
        action TEXT,
        target TEXT,
        timestamp TEXT
    )''')
    try:
        conn.execute("SELECT last_payout_date FROM term_deposits LIMIT 1")
    except sqlite3.OperationalError:
        print("Migrating DB: Adding 'last_payout_date' column to term_deposits table...")
        conn.execute("ALTER TABLE term_deposits ADD COLUMN last_payout_date TEXT")
        conn.commit()
    conn.close()
    
# --- HELPERS ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_transaction(account_id, t_type, currency, amount, note="", status="COMPLETED", conn=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True
    
    conn.execute(
        "INSERT INTO transactions (account_id, timestamp, type, currency, amount, note, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (account_id, timestamp, t_type, currency, amount, note, status),
    )
    conn.commit()
    if should_close: conn.close()

def log_admin_action(admin_id, action, target, conn):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO admin_logs (admin_id, action, target, timestamp) VALUES (?, ?, ?, ?)",
        (admin_id, action, target, timestamp),
    )

def is_hashed_pin(pin):
    return isinstance(pin, str) and (pin.startswith("pbkdf2:") or pin.startswith("scrypt:"))

def verify_and_upgrade_pin(stored_pin, provided_pin, update_cb=None):
    if stored_pin is None:
        return False
    if is_hashed_pin(stored_pin):
        return check_password_hash(stored_pin, provided_pin)
    if stored_pin == provided_pin:
        if update_cb:
            update_cb(generate_password_hash(provided_pin))
        return True
    return False

def add_months(source_date, months):
    month_index = source_date.month - 1 + months
    year = source_date.year + month_index // 12
    month = month_index % 12 + 1
    day = min(source_date.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
    return source_date.replace(year=year, month=month, day=day)

def months_between(start_date, end_date):
    return (end_date.year - start_date.year) * 12 + (end_date.month - start_date.month)

def process_matured_deposits(conn, account_id):
    today = datetime.now().date()
    rows = conn.execute(
        "SELECT * FROM term_deposits WHERE account_id=? AND status='ACTIVE'",
        (account_id,),
    ).fetchall()
    for dep in rows:
        if not dep['end_date']:
            continue
        end_date = datetime.strptime(dep['end_date'], "%Y-%m-%d").date()
        payout_card = dep['payout_card_number']
        conn.execute(
            "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
            (payout_card,),
        )

        if dep['is_monthly_payout']:
            if not dep['start_date'] or not dep['term_months']:
                continue
            start_date = datetime.strptime(dep['start_date'], "%Y-%m-%d").date()
            last_payout_str = dep['last_payout_date'] or dep['start_date']
            last_payout_date = datetime.strptime(last_payout_str, "%Y-%m-%d").date()
            payout_until = min(today, end_date)
            next_payout_date = add_months(last_payout_date, 1)
            months_due = 0
            while next_payout_date <= payout_until:
                months_due += 1
                next_payout_date = add_months(next_payout_date, 1)

            monthly_interest = dep['projected_profit'] / dep['term_months']
            if months_due > 0 and monthly_interest > 0:
                interest_to_pay = monthly_interest * months_due
                conn.execute(
                    "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
                    (interest_to_pay, payout_card),
                )
                last_payout_date = add_months(last_payout_date, months_due)
                conn.execute(
                    "UPDATE term_deposits SET last_payout_date=? WHERE id=?",
                    (last_payout_date.strftime("%Y-%m-%d"), dep['id']),
                )
                log_transaction(
                    account_id,
                    "DEPOSIT_INTEREST",
                    dep['currency'],
                    interest_to_pay,
                    f"Monthly interest payout to {payout_card[-4:]}",
                    conn=conn,
                )

            if end_date <= today:
                months_paid = min(dep['term_months'], months_between(start_date, last_payout_date))
                total_interest_paid = monthly_interest * months_paid
                remaining_interest = max(dep['projected_profit'] - total_interest_paid, 0)
                payout_amount = dep['amount'] + remaining_interest
                if payout_amount > 0:
                    conn.execute(
                        "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
                        (payout_amount, payout_card),
                    )
                conn.execute(
                    "UPDATE term_deposits SET status='COMPLETED', last_payout_date=? WHERE id=?",
                    (end_date.strftime("%Y-%m-%d"), dep['id']),
                )
                log_transaction(
                    account_id,
                    "DEPOSIT_PAYOUT",
                    dep['currency'],
                    payout_amount,
                    f"Deposit matured to {payout_card[-4:]}",
                    conn=conn,
                )
        else:
            if end_date > today:
                continue
            payout_amount = dep['amount'] + dep['projected_profit']
            conn.execute(
                "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
                (payout_amount, payout_card),
            )
            conn.execute(
                "UPDATE term_deposits SET status='COMPLETED' WHERE id=?",
                (dep['id'],),
            )
            log_transaction(
                account_id,
                "DEPOSIT_PAYOUT",
                dep['currency'],
                payout_amount,
                f"Deposit matured to {payout_card[-4:]}",
                conn=conn,
            )

def parse_transfer_note(note):
    if not note:
        return None
    match = re.search(r"Transfer (\d+)->(\d+)", note)
    if not match:
        return None
    return match.group(1), match.group(2)

def complete_pending_transfer(conn, tx_row, admin_id):
    card_pair = parse_transfer_note(tx_row['note'])
    if not card_pair:
        return False, "Unable to parse transfer details."
    sender_card_num, receiver_card_num = card_pair
    if tx_row['status'] != "PENDING":
        return False, "Transfer is not pending."

    conn.execute(
        "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
        (receiver_card_num,),
    )
    conn.execute(
        "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
        (abs(tx_row['amount']), receiver_card_num),
    )

    conn.execute(
        "UPDATE transactions SET status='COMPLETED' WHERE id=?",
        (tx_row['id'],),
    )
    conn.execute(
        "UPDATE transactions SET status='COMPLETED' "
        "WHERE type='RECEIVED' AND note=? AND status='PENDING'",
        (tx_row['note'],),
    )
    conn.execute(
        "UPDATE transactions SET status='COMPLETED' "
        "WHERE type='FEE' AND note LIKE ? AND status='PENDING'",
        (f"%{tx_row['note']}%",),
    )

    log_admin_action(admin_id, "COMPLETE_TRANSFER", str(tx_row['id']), conn)
    return True, "Transfer completed."

def reverse_transfer(conn, tx_row, admin_id):
    card_pair = parse_transfer_note(tx_row['note'])
    if not card_pair:
        return False, "Unable to parse transfer details."
    sender_card_num, receiver_card_num = card_pair
    if tx_row['status'] == "REVERSED":
        return False, "Transfer already reversed."

    amount = abs(tx_row['amount'])
    conn.execute(
        "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
        (sender_card_num,),
    )
    conn.execute(
        "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
        (amount, sender_card_num),
    )

    if tx_row['status'] == "COMPLETED":
        conn.execute(
            "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
            (receiver_card_num,),
        )
        conn.execute(
            "UPDATE card_balances SET amount = amount - ? WHERE card_number=?",
            (amount, receiver_card_num),
        )

    fee_rows = conn.execute(
        "SELECT id, amount FROM transactions WHERE type='FEE' AND note LIKE ? AND account_id=?",
        (f"%{tx_row['note']}%", tx_row['account_id']),
    ).fetchall()
    for fee in fee_rows:
        conn.execute(
            "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
            (abs(fee['amount']), sender_card_num),
        )
        conn.execute(
            "UPDATE transactions SET status='REVERSED' WHERE id=?",
            (fee['id'],),
        )

    conn.execute(
        "UPDATE transactions SET status='REVERSED' WHERE id=?",
        (tx_row['id'],),
    )
    conn.execute(
        "UPDATE transactions SET status='REVERSED' "
        "WHERE type='RECEIVED' AND note=? AND status!='REVERSED'",
        (tx_row['note'],),
    )

    log_admin_action(admin_id, "REVERSE_TRANSFER", str(tx_row['id']), conn)
    return True, "Transfer reversed."

@app.before_request
def enforce_session_security():
    if 'user_id' not in session:
        return
    current_ip = request.remote_addr
    stored_ip = session.get('ip')
    last_seen = session.get('last_activity')
    now = datetime.utcnow().timestamp()
    if stored_ip and stored_ip != current_ip:
        session.clear()
        flash("Session ended due to IP change.", "warning")
        return redirect(url_for('login'))
    if last_seen and (now - last_seen) > app.permanent_session_lifetime.total_seconds():
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('login'))
    session['last_activity'] = now

def process_bonus(user_id, currency, transfer_amount):
    """1% cashback logic"""
    bonus_amount = transfer_amount * 0.01
    current_month = datetime.now().strftime("%Y-%m")
    conn = get_db()
    
    row = conn.execute("SELECT balance, earned_this_month, last_month_str FROM bonuses WHERE account_id=? AND currency=?", 
                       (user_id, currency)).fetchone()

    if not row:
        current_bal, earned_month, last_month = 0.0, 0.0, current_month
        conn.execute("INSERT INTO bonuses VALUES (?, ?, 0, 0, ?)", (user_id, currency, current_month))
    else:
        current_bal, earned_month, last_month = row['balance'], row['earned_this_month'], row['last_month_str']

    if last_month != current_month:
        earned_month = 0.0
        last_month = current_month

    remaining_cap = 10.0 - earned_month
    if remaining_cap > 0:
        final_bonus = min(bonus_amount, remaining_cap)
        if final_bonus > 0:
            conn.execute('''UPDATE bonuses SET balance=?, earned_this_month=?, last_month_str=? 
                            WHERE account_id=? AND currency=?''',
                         (current_bal + final_bonus, earned_month + final_bonus, last_month, user_id, currency))
            flash(f"BONUS: You earned {final_bonus:.2f} {currency} cashback!", "success")
    
    conn.commit()
    conn.close()

# --- CORE ROUTES ---

@app.route('/')
def index():
    if 'user_id' in session:
        # FIX: Check if Admin, send to Admin Panel. If User, send to Dashboard.
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid = request.form['id']
        pin = request.form['pin']
        
        # Admin Login
        if uid == "0000" and pin == "1234":
            session['user_id'] = "9999"
            session['is_admin'] = True
            session['name'] = "Administrator"
            session['ip'] = request.remote_addr
            session['last_activity'] = datetime.utcnow().timestamp()
            return redirect(url_for('admin'))
            
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE account_id=?", (uid,)).fetchone()
        
        if user and verify_and_upgrade_pin(
            user['pin'],
            pin,
            update_cb=lambda new_pin: conn.execute(
                "UPDATE users SET pin=? WHERE account_id=?",
                (new_pin, uid),
            ),
        ):
            if user['status'] != 'ACTIVE':
                flash("Account is not active. Please contact support.", "warning")
                conn.close()
                return render_template('login.html')
            session['user_id'] = user['account_id']
            session['name'] = user['name']
            session['profile_pic'] = user['profile_pic'] # V7 Feature
            session['is_admin'] = False
            session['ip'] = request.remote_addr
            session['last_activity'] = datetime.utcnow().timestamp()
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash("Invalid ID or PIN", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        id_card = request.form['id_card'].upper()
        pin = request.form['pin']
        
        if not re.match(r'^[A-Z0-9]{7}$', id_card):
            flash("ID must be 7 chars (A-Z, 0-9)", "warning")
            return redirect(url_for('register'))
            
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        new_id = str(1001 + count)
        
        try:
            # INSERT with 'PENDING' status
            hashed_pin = generate_password_hash(pin)
            conn.execute(
                "INSERT INTO users (account_id, name, pin, email, phone, id_card, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (new_id, name, hashed_pin, email, phone, id_card, 'PENDING'),
            )
            conn.execute("INSERT INTO balances VALUES (?, ?, ?)", (new_id, "AZN", 0.0))
            conn.commit()
            flash(f"Registration Successful! Your ID is {new_id}. Please wait for Admin Approval.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("ID Card already exists", "danger")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        finally:
            conn.close()
    return render_template('register.html')

# --- 3. UPDATE DASHBOARD ROUTE (Fetch Deposits) ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    # Security check for admin...
    if session.get('is_admin'): return redirect(url_for('admin'))

    uid = session['user_id']
    conn = get_db()
    
    process_matured_deposits(conn, uid)

    # 1. Get Cards with per-card balances
    db_cards = conn.execute(
        """
        SELECT cards.*, COALESCE(card_balances.amount, 0) AS balance
        FROM cards
        LEFT JOIN card_balances ON cards.card_number = card_balances.card_number
        WHERE cards.account_id=?
        """,
        (uid,),
    ).fetchall()

    cards_with_balance = [dict(card) for card in db_cards]
    
    # 3. NEW: Get Active Deposits
    my_deposits = conn.execute("SELECT * FROM term_deposits WHERE account_id=? AND status='ACTIVE'", (uid,)).fetchall()
    
    # Stats
    tx_count = conn.execute("SELECT COUNT(*) FROM transactions WHERE account_id=?", (uid,)).fetchone()[0]
    conn.close()
    
    # NOTE: We removed 'balances' from the render variable since user wanted to hide wallet section
    # But we still pass cards_with_balance so they can see funds on cards.
    return render_template('dashboard.html', 
                           deposits=my_deposits, 
                           cards=cards_with_balance, 
                           tx_count=tx_count)

# --- V7 FEATURES (Chat, Profile, Notifications) ---

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()

    if request.method == 'POST':
        # Upload Pic
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{uid}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                conn.execute("UPDATE users SET profile_pic=? WHERE account_id=?", (filename, uid))
                session['profile_pic'] = filename
                flash("Profile picture updated!", "success")
        
        # Update Details
        if 'email' in request.form:
            conn.execute("UPDATE users SET email=?, phone=? WHERE account_id=?", 
                         (request.form['email'], request.form['phone'], uid))
            flash("Contact info updated!", "success")
        
        conn.commit()
        return redirect(url_for('profile'))

    user = conn.execute("SELECT * FROM users WHERE account_id=?", (uid,)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/api/notifications')
def get_notifications():
    if 'user_id' not in session: return jsonify([])
    conn = get_db()
    txs = conn.execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 5", (session['user_id'],)).fetchall()
    conn.close()
    
    data = []
    for t in txs:
        data.append({
            'timestamp': t['timestamp'],
            'message': f"{t['type']} {t['amount']} {t['currency']} - {t['note']}"
        })
    return jsonify(data)

@app.route('/api/chat/send', methods=['POST'])
def send_chat():
    if 'user_id' not in session: return jsonify({'status': 'error'})
    uid = session['user_id']
    msg = request.form.get('message')
    if msg:
        conn = get_db()
        ts = datetime.now().strftime("%H:%M")
        conn.execute("INSERT INTO chats (account_id, sender, message, timestamp) VALUES (?, ?, ?, ?)", 
                     (uid, 'USER', msg, ts))
        conn.commit()
        
        # Auto-reply Simulation
        if "help" in msg.lower():
            conn.execute("INSERT INTO chats (account_id, sender, message, timestamp) VALUES (?, ?, ?, ?)", 
                         (uid, 'ADMIN', "Support: We have received your request. An agent will reply shortly.", ts))
            conn.commit()
            
        conn.close()
    return jsonify({'status': 'ok'})

@app.route('/api/chat/get')
def get_chat():
    if 'user_id' not in session: return jsonify([])
    uid = session['user_id']
    conn = get_db()
    msgs = conn.execute("SELECT * FROM chats WHERE account_id=? ORDER BY id ASC LIMIT 50", (uid,)).fetchall()
    conn.close()
    return jsonify([dict(m) for m in msgs])

# --- FINANCIAL ROUTES (Transfer, Topup, Cards) ---
#tansfer 1.1v
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    
    try:
        if request.method == 'POST':
            sender_card_num = request.form['sender_card']
            receiver_card_num = request.form['receiver_card']
            try: amount = float(request.form['amount'])
            except: amount = 0
            pin = request.form['pin']
            
            sender_card = conn.execute(""" SELECT * FROM cards WHERE card_number=? AND account_id=? """, (sender_card_num, uid)).fetchone()
            pin_valid = False
            if sender_card:
                pin_valid = verify_and_upgrade_pin(
                    sender_card['card_pin'],
                    pin,
                    update_cb=lambda new_pin: conn.execute(
                        "UPDATE cards SET card_pin=? WHERE card_number=?",
                        (new_pin, sender_card_num),
                    ),
                )
            if not sender_card:
                flash("Sender card not found.", "danger")
                return redirect(url_for('transfer'))
            elif sender_card['status'] != 'ACTIVE':
                flash("Sender card is not ACTIVE.", "danger")
                return redirect(url_for('transfer'))
            elif not pin_valid:
                flash("Invalid PIN.", "danger")
                return redirect(url_for('transfer'))

            rcv = conn.execute("SELECT account_id, status, currency FROM cards WHERE card_number=?", (receiver_card_num,)).fetchone()
            
            # --- UPDATED FEE LOGIC (Excess Only) ---
            total_fee = 0.0
            fee_note = ""
            if amount > 5000:
                excess_amount = amount - 5000
                # Fee is 2% of the EXCESS amount, but minimum 1.0
                total_fee = max(excess_amount * 0.02, 1.0)
                fee_note = f"Fee (2% on {excess_amount} excess)"

            total_deduction = amount + total_fee
            # ---------------------------------------

            # Validation
            if amount <= 0:
                flash("Amount must be positive.", "danger")
            elif not sender_card or not pin_valid:
                flash("Invalid Card or PIN", "danger")
            elif not rcv: flash("Receiver not found", "danger")
            elif rcv['status'] != 'ACTIVE': flash("Receiver card inactive", "danger")
            elif rcv['currency'] != sender_card['currency']: flash("Currency mismatch.", "danger")
            elif rcv['account_id'] == uid and receiver_card_num == sender_card_num:
                flash("Cannot send to the same card.", "warning")
            elif amount > sender_card['expense_limit']: 
                flash(f"Amount exceeds your card limit of {sender_card['expense_limit']}", "danger")
            else:
                conn.execute(
                    "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
                    (sender_card_num,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
                    (receiver_card_num,),
                )
                bal_row = conn.execute(
                    "SELECT amount FROM card_balances WHERE card_number=?",
                    (sender_card_num,),
                ).fetchone()
                bal = bal_row['amount'] if bal_row else 0.0
                
                if total_deduction > bal:
                    flash(f"Insufficient funds. Total needed: {total_deduction:.2f} (Amount + {total_fee} Fee)", "danger")
                else:
                    # Execute Transfer (Per-card balances)
                    conn.execute(
                        "UPDATE card_balances SET amount=? WHERE card_number=?",
                        (bal - total_deduction, sender_card_num),
                    )

                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    curr = sender_card['currency']
                    note = f"Transfer {sender_card_num}->{receiver_card_num}"
                    transfer_status = (
                        "PENDING" if amount >= TRANSFER_PENDING_THRESHOLD else "COMPLETED"
                    )

                    if transfer_status == "COMPLETED":
                        rcv_bal_row = conn.execute(
                            "SELECT amount FROM card_balances WHERE card_number=?",
                            (receiver_card_num,),
                        ).fetchone()
                        if not rcv_bal_row:
                            conn.execute(
                                "INSERT INTO card_balances (card_number, amount) VALUES (?, ?)",
                                (receiver_card_num, amount),
                            )
                        else:
                            conn.execute(
                                "UPDATE card_balances SET amount=? WHERE card_number=?",
                                (rcv_bal_row['amount'] + amount, receiver_card_num),
                            )

                    conn.execute(
                        "INSERT INTO transactions (account_id, timestamp, type, currency, amount, note, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (uid, ts, "SENT", curr, -amount, note, transfer_status),
                    )

                    if total_fee > 0:
                        conn.execute(
                            "INSERT INTO transactions (account_id, timestamp, type, currency, amount, note, status) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (uid, ts, "FEE", curr, -total_fee, f"{fee_note} | {note}", transfer_status),
                        )

                    conn.execute(
                        "INSERT INTO transactions (account_id, timestamp, type, currency, amount, note, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (rcv['account_id'], ts, "RECEIVED", curr, amount, note, transfer_status),
                    )
                    
                    conn.commit()
                    if transfer_status == "COMPLETED":
                        process_bonus(uid, curr, amount)
                        flash(f"Sent {amount} {curr} successfully!", "success")
                    else:
                        flash(
                            f"Transfer pending approval. {amount} {curr} is on hold.",
                            "warning",
                        )
                    return redirect(url_for('history'))

        # Prepare data for form
        db_cards = conn.execute(
            """
            SELECT cards.*, COALESCE(card_balances.amount, 0) AS balance
            FROM cards
            LEFT JOIN card_balances ON cards.card_number = card_balances.card_number
            WHERE cards.account_id=? AND cards.status='ACTIVE'
            """,
            (uid,),
        ).fetchall()
        
        active_cards_with_bal = [dict(card) for card in db_cards]

        return render_template('transfer.html', cards=active_cards_with_bal)
    except Exception as e:
        print(e)
        return redirect(url_for('transfer'))
    finally:
        try: conn.close()
        except: pass

@app.route('/topup', methods=['GET', 'POST'])
def topup():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    
    try:
        if request.method == 'POST':
            card_num = request.form['card_num']
            try: amount = float(request.form['amount'])
            except: amount = 0
            
            if amount <= 0:
                flash("Amount must be positive.", "warning")
            else:
                card = conn.execute("""SELECT currency, status FROM cards WHERE card_number=? AND account_id=?""", (card_num, uid)).fetchone()
                if not card:
                    flash("Card not found.", "danger")
                elif card['status'] != 'ACTIVE':
                    flash("Card must be ACTIVE to top up.", "danger")
                if card and card['status'] == 'ACTIVE':
                    curr = card['currency']
                    bal_row = conn.execute(
                        "SELECT amount FROM card_balances WHERE card_number=?",
                        (card_num,),
                    ).fetchone()
                    current_bal = bal_row['amount'] if bal_row else 0.0
                    
                    if not bal_row:
                        conn.execute(
                            "INSERT INTO card_balances (card_number, amount) VALUES (?, ?)",
                            (card_num, amount),
                        )
                    else:
                        conn.execute(
                            "UPDATE card_balances SET amount=? WHERE card_number=?",
                            (current_bal + amount, card_num),
                        )
                    
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute("INSERT INTO transactions (account_id, timestamp, type, currency, amount, note) VALUES (?, ?, ?, ?, ?, ?)",
                                 (uid, ts, "DEPOSIT", curr, amount, f"Top Up via Card {card_num[-4:]}"))
                    conn.commit()
                    flash(f"Added {amount} {curr}!", "success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("Card not found or inactive.", "danger")
        
        my_cards = conn.execute("SELECT * FROM cards WHERE account_id=? AND status='ACTIVE'", (uid,)).fetchall()
        return render_template('topup.html', cards=my_cards)
    finally:
        conn.close()

@app.route('/cards')
def cards():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    db_cards = conn.execute(
        """
        SELECT cards.*, COALESCE(card_balances.amount, 0) AS balance
        FROM cards
        LEFT JOIN card_balances ON cards.card_number = card_balances.card_number
        WHERE cards.account_id=?
        """,
        (uid,),
    ).fetchall()
    
    cards_out = [dict(card) for card in db_cards]
    conn.close()
    return render_template('cards.html', cards=cards_out)

#new update
@app.route('/card_settings/<card_num>', methods=['GET', 'POST'])
def card_settings(card_num):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    def get_card():
        return conn.execute(
            "SELECT * FROM cards WHERE card_number=? AND account_id=?",
            (card_num, session['user_id'])
        ).fetchone()

    card = get_card()
    if not card:
        conn.close()
        return redirect(url_for('cards'))

    if request.method == 'POST':
        action = request.form.get('action', '')

        # Do not allow changes for pending cards
        if card['status'] == 'PENDING':
            flash("This card is pending approval — settings are locked.", "warning")
            conn.close()
            return redirect(url_for('card_settings', card_num=card_num))

        if action == 'rename':
            new_name = request.form.get('new_name', '').strip()
            if not new_name:
                flash("Card name cannot be empty.", "danger")
            else:
                conn.execute(
                    "UPDATE cards SET card_name=? WHERE card_number=? AND account_id=?",
                    (new_name, card_num, session['user_id'])
                )
                conn.commit()
                flash("Card name updated.", "success")

        elif action == 'change_pin':
            new_pin = request.form.get('new_pin', '').strip()
            confirm_pin = request.form.get('confirm_pin', '').strip()

            if new_pin != confirm_pin:
                flash("PINs do not match.", "danger")
            elif len(new_pin) != 4 or not new_pin.isdigit():
                flash("PIN must be exactly 4 digits (0-9).", "danger")
            else:
                conn.execute(
                    "UPDATE cards SET card_pin=? WHERE card_number=? AND account_id=?",
                    (generate_password_hash(new_pin), card_num, session['user_id'])
                )
                conn.commit()
                flash("PIN updated successfully.", "success")

        elif action == 'change_limit':
            try:
                new_limit = float(request.form.get('new_limit', ''))
                if new_limit < 0:
                    raise ValueError
                conn.execute(
                    "UPDATE cards SET expense_limit=? WHERE card_number=? AND account_id=?",
                    (new_limit, card_num, session['user_id'])
                )
                conn.commit()
                flash("Spending limit updated.", "success")
            except:
                flash("Please enter a valid limit.", "danger")

        elif action == 'toggle_block':
            new_status = 'BLOCKED' if card['status'] == 'ACTIVE' else 'ACTIVE'
            conn.execute(
                "UPDATE cards SET status=? WHERE card_number=? AND account_id=?",
                (new_status, card_num, session['user_id'])
            )
            conn.commit()
            flash("Card status updated.", "success")

        else:
            flash("Unknown action.", "danger")

        # Refresh card so changes show immediately
        card = get_card()
        conn.close()
        return redirect(url_for('card_settings', card_num=card_num))

    conn.close()
    return render_template('card_settings.html', card=card)

@app.route('/order_card', methods=['GET', 'POST'])
def order_card():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    
    if request.method == 'POST':
        conn = get_db()
        
        # 1. Security: Check if User is Verified
        user = conn.execute("SELECT status FROM users WHERE account_id=?", (uid,)).fetchone()
        if user['status'] != 'ACTIVE':
            flash("Account must be Verified by Admin to order cards.", "warning")
            conn.close()
            return redirect(url_for('cards'))

        # 2. Check Card Limit
        count = conn.execute("SELECT COUNT(*) FROM cards WHERE account_id=?", (uid,)).fetchone()[0]
        if count >= 3:
            flash("Max 3 Cards allowed", "danger")
        else:
            currency = request.form['currency']
            ctype = request.form['card_type']
            
            # --- CARD NUMBER GENERATION ---
            
            # Step 1: Prefix & Bank Code
            # User defined: Visa=4320022, Master=5554523
            def generate_card_number(ctype):
                if ctype == "VISA":
                    prefix, bank_code = "4", "4320022"
                else:
                    prefix, bank_code = "5", "5554523"
                unique = ''.join(str(random.randint(0, 9)) for _ in range(8))
                return prefix + bank_code + unique
            
            # Format: 1-digit prefix + 7-digit bank code + 8-digit unique = 16 digits
            c_num = None
            for _ in range(10):
                candidate = generate_card_number(ctype)
                exists = conn.execute("SELECT 1 FROM cards WHERE card_number=?", (candidate,)).fetchone()
                if not exists:
                    c_num = candidate
                    break
            
            if not c_num:
                flash("Could not generate a unique card number. Try again.", "danger")
                conn.close()
                return redirect(url_for('cards'))
            # Example Result: 4432002212345678
            # ------------------------------

            cvc = ''.join([str(random.randint(0,9)) for _ in range(3)])
            pin = ''.join([str(random.randint(0,9)) for _ in range(4)])
            hashed_pin = generate_password_hash(pin)
            exp = datetime.now().replace(year=datetime.now().year + 3).strftime("%m/%y")
            
            conn.execute(
                "INSERT INTO cards (card_number, account_id, cvc, status, expiry, card_type, currency, card_pin) VALUES (?, ?, ?, 'PENDING', ?, ?, ?, ?)",
                (c_num, uid, cvc, exp, ctype, currency, hashed_pin),
            )
            conn.execute(
                "INSERT INTO card_balances (card_number, amount) VALUES (?, 0)",
                (c_num,),
            )
            conn.commit()
            flash(f"Ordered! PIN: {pin}", "success")
        conn.close()
        return redirect(url_for('cards'))
    return render_template('order_card.html')

@app.route('/bonuses')
def bonuses():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    my_bonuses = conn.execute("SELECT * FROM bonuses WHERE account_id=?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('bonuses.html', bonuses=my_bonuses)

@app.route('/claim_bonus/<currency>')
def claim_bonus(currency):
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    row = conn.execute("SELECT balance FROM bonuses WHERE account_id=? AND currency=?", (uid, currency)).fetchone()
    
    if row and row['balance'] >= 1.0:
        cur_bal = conn.execute("SELECT amount FROM balances WHERE account_id=? AND currency=?", (uid, currency)).fetchone()
        wallet_amount = cur_bal['amount'] if cur_bal else 0.0
        
        if not cur_bal: conn.execute("INSERT INTO balances VALUES (?, ?, ?)", (uid, currency, row['balance']))
        else: conn.execute("UPDATE balances SET amount=? WHERE account_id=? AND currency=?", (wallet_amount + row['balance'], uid, currency))
        
        conn.execute("UPDATE bonuses SET balance=0 WHERE account_id=? AND currency=?", (uid, currency))
        log_transaction(uid, "BONUS_CLAIM", currency, row['balance'], "Claimed Cashback", conn)
        conn.commit()
        flash("Bonus Claimed!", "success")
    else:
        flash("Minimum 1.00 required", "warning")
    
    conn.close()
    return redirect(url_for('bonuses'))

# --- history
@app.route('/history')
def history():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    
    # 1. Fetch Transactions
    txs = conn.execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 20", (session['user_id'],)).fetchall()
    
    # 2. Calculate Chart Data (Income vs Expense)
    income = 0
    expense = 0
    for t in txs:
        if t['status'] != 'COMPLETED':
            continue
        if t['amount'] > 0:
            income += t['amount']
        else:
            expense += abs(t['amount'])
            
    conn.close()
    
    # Pass data to template
    return render_template('history.html', txs=txs, chart_income=income, chart_expense=expense)

@app.route('/support', methods=['GET', 'POST'])
def support():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    if request.method == 'POST':
        conn.execute("INSERT INTO tickets (account_id, issue, timestamp) VALUES (?, ?, ?)", 
                     (uid, request.form['issue'], datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()
        flash("Ticket Submitted", "success")
    tickets = conn.execute("SELECT * FROM tickets WHERE account_id=?", (uid,)).fetchall()
    conn.close()
    return render_template('support.html', tickets=tickets)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # 1. Security Check
    if not session.get('is_admin'): 
        return redirect(url_for('login'))
    
    conn = get_db()
    
    # 2. Handle Actions (Approve User, Suspend User, APPROVE CARD, Transfers)
    if 'action' in request.args and 'target_id' in request.args:
        action = request.args.get('action')
        target = request.args.get('target_id')
        
        msg = ""
        
        if action == 'suspend':
            conn.execute("UPDATE users SET status='SUSPENDED' WHERE account_id=?", (target,))
            msg = f"User {target} SUSPENDED."
            log_admin_action(session.get('user_id'), "SUSPEND_USER", target, conn)
            
        elif action == 'unsuspend':
            conn.execute("UPDATE users SET status='ACTIVE' WHERE account_id=?", (target,))
            msg = f"User {target} REACTIVATED."
            log_admin_action(session.get('user_id'), "UNSUSPEND_USER", target, conn)
            
        elif action == 'approve_user':
            conn.execute("UPDATE users SET status='ACTIVE' WHERE account_id=?", (target,))
            msg = f"User {target} APPROVED."
            log_admin_action(session.get('user_id'), "APPROVE_USER", target, conn)

        # --- NEW: CARD APPROVAL LOGIC ---
        elif action == 'approve_card':
            conn.execute("UPDATE cards SET status='ACTIVE' WHERE card_number=?", (target,))
            msg = f"Card {target} is now ACTIVE."
            log_admin_action(session.get('user_id'), "APPROVE_CARD", target, conn)
        # --------------------------------
        elif action == 'complete_transfer':
            tx_row = conn.execute("SELECT * FROM transactions WHERE id=?", (target,)).fetchone()
            if not tx_row:
                msg = "Transaction not found."
            elif tx_row['type'] != 'SENT':
                msg = "Only SENT transfers can be completed."
            else:
                ok, result = complete_pending_transfer(conn, tx_row, session.get('user_id'))
                msg = result
        elif action == 'reverse_transfer':
            tx_row = conn.execute("SELECT * FROM transactions WHERE id=?", (target,)).fetchone()
            if not tx_row:
                msg = "Transaction not found."
            elif tx_row['type'] != 'SENT':
                msg = "Only SENT transfers can be reversed."
            else:
                ok, result = reverse_transfer(conn, tx_row, session.get('user_id'))
                msg = result
            
        conn.commit()
        flash(msg, "success")
        return redirect(url_for('admin'))

    # 3. Fetch Pending Cards Queue (For the new section)
    pending_cards = conn.execute("SELECT * FROM cards WHERE status='PENDING'").fetchall()

    # 4. Handle User Search (Standard Logic)
    query = request.form.get('search_query') or request.args.get('search_query')
    searched_user = None
    user_cards = []
    user_txs = []
    user_bals = []
    suspicious = []
    
    if query:
        searched_user = conn.execute("SELECT * FROM users WHERE account_id=? OR id_card=? OR email=?", (query, query, query)).fetchone()
        if searched_user:
            uid = searched_user['account_id']
            user_bals = conn.execute("SELECT * FROM balances WHERE account_id=?", (uid,)).fetchall()
            user_cards = conn.execute("SELECT * FROM cards WHERE account_id=?", (uid,)).fetchall()
            user_txs = conn.execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 50", (uid,)).fetchall()
            suspicious = conn.execute("SELECT * FROM transactions WHERE account_id=? AND (abs(amount) > 5000 OR type='FEE') ORDER BY id DESC", (uid,)).fetchall()

    conn.close()
    
    # Pass 'pending_cards' to the template
    return render_template('admin.html', 
                           user=searched_user, 
                           cards=user_cards, 
                           txs=user_txs, 
                           balances=user_bals, 
                           suspicious=suspicious, 
                           search_query=query,
                           pending_cards=pending_cards)

@app.route('/create_deposit', methods=['POST'])
def create_deposit():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    conn = get_db()
    
    try:
        source_card_num = request.form['source_card']
        payout_card_num = request.form['payout_card']
        amount = float(request.form['amount'])
        currency = request.form['currency']
        months = int(request.form['term_months'])
        payout_type = request.form['payout_type'] # 'end' or 'monthly'
        
        # 1. Validation: Min/Max
        if amount < 200 or amount > 500000:
            flash(f"Amount must be between 200 and 500,000 {currency}", "warning")
            return redirect(url_for('dashboard'))

        # 2. Get Source Card & Balance
        card = conn.execute("SELECT * FROM cards WHERE card_number=? AND account_id=?", (source_card_num, uid)).fetchone()
        if not card or card['currency'] != currency:
            flash("Invalid Source Card or Currency Mismatch", "danger")
            return redirect(url_for('dashboard'))
        if card['status'] != 'ACTIVE':
            flash("Source card must be ACTIVE.", "danger")
            return redirect(url_for('dashboard'))

        payout_card = conn.execute(
            "SELECT * FROM cards WHERE card_number=? AND account_id=?",
            (payout_card_num, uid),
        ).fetchone()
        if not payout_card or payout_card['currency'] != currency:
            flash("Invalid payout card or currency mismatch.", "danger")
            return redirect(url_for('dashboard'))
        if payout_card['status'] != 'ACTIVE':
            flash("Payout card must be ACTIVE.", "danger")
            return redirect(url_for('dashboard'))
            
        conn.execute(
            "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
            (source_card_num,),
        )
        bal_row = conn.execute(
            "SELECT amount FROM card_balances WHERE card_number=?",
            (source_card_num,),
        ).fetchone()
        balance = bal_row['amount'] if bal_row else 0.0
        
        if balance < amount:
            flash("Insufficient funds on source card for this deposit.", "danger")
            return redirect(url_for('dashboard'))

        # 3. Calculate Rate (Exact Logic from Prompt)
        base_rate = 0.0
        
        if currency == 'AZN':
            if months == 6: base_rate = 8.0
            elif months == 9: base_rate = 9.0
            elif months == 12: base_rate = 11.0
            elif months == 18: base_rate = 10.0
            elif months == 24: base_rate = 10.5
        elif currency == 'USD':
            if months == 12: base_rate = 3.0
            elif months == 24: base_rate = 3.5
        elif currency == 'EUR':
            if months == 18: base_rate = 3.5

        if base_rate == 0.0:
            flash("Invalid Term selected for this currency.", "danger")
            return redirect(url_for('dashboard'))

        # Apply Monthly Penalty (-0.5%)
        is_monthly = (payout_type == 'monthly')
        final_rate = base_rate - 0.5 if is_monthly else base_rate
        
        # Calculate Projected Profit
        # Formula: Amount * (Rate/100) * (Months/12)
        profit = amount * (final_rate / 100) * (months / 12)

        # 4. Execute Transaction
        # Deduct Money
        conn.execute(
            "UPDATE card_balances SET amount=? WHERE card_number=?",
            (balance - amount, source_card_num),
        )
        
        # Log Transaction
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO transactions (account_id, timestamp, type, currency, amount, note, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, ts, "INVEST", currency, -amount, f"Opened {months}-Month Deposit ({final_rate}%)", "COMPLETED"),
        )
        
        # Create Deposit Record
        # End Date Calculation
        start_date_dt = datetime.now().date()
        start_date = start_date_dt.strftime("%Y-%m-%d")
        end_date = add_months(start_date_dt, months).strftime("%Y-%m-%d")
        
        last_payout_date = start_date if is_monthly else None
        conn.execute('''INSERT INTO term_deposits 
            (account_id, amount, currency, term_months, interest_rate, is_monthly_payout, start_date, end_date, last_payout_date, payout_card_number, projected_profit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (uid, amount, currency, months, final_rate, 1 if is_monthly else 0, start_date, end_date, last_payout_date, payout_card_num, profit))
            
        conn.commit()
        flash(f"Success! Invested {amount} {currency} at {final_rate}%", "success")
        
    except Exception as e:
        print(e)
        flash("Error processing deposit.", "danger")
        
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

# --- CURRENCY EXCHANGE ROUTE ---
@app.route('/exchange', methods=['GET', 'POST'])
def exchange():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    uid = session['user_id']
    conn = get_db()
    
    # 1. Fetch Active Cards with Balances
    cards = conn.execute(
        """
        SELECT cards.*, COALESCE(card_balances.amount, 0) AS balance
        FROM cards
        LEFT JOIN card_balances ON cards.card_number = card_balances.card_number
        WHERE cards.account_id=? AND cards.status='ACTIVE'
        """,
        (uid,),
    ).fetchall()
    card_lookup = {card['card_number']: card for card in cards}
    
    # 2. Define Exchange Rates (Hardcoded for simplicity)
    # format: 'FROM_TO' : rate
    rates = {
        'USD_AZN': 1.70, 'AZN_USD': 0.588,
        'EUR_AZN': 1.85, 'AZN_EUR': 0.540,
        'EUR_USD': 1.09, 'USD_EUR': 0.917,
        'USD_USD': 1.0,  'AZN_AZN': 1.0, 'EUR_EUR': 1.0
    }

    if request.method == 'POST':
        from_card_num = request.form['from_card']
        to_card_num = request.form['to_card']
        try:
            amount = float(request.form['amount'])
        except ValueError:
            flash("Invalid amount.", "danger")
            return redirect(url_for('exchange'))

        from_card = card_lookup.get(from_card_num)
        to_card = card_lookup.get(to_card_num)

        # Security Checks
        if amount <= 0:
            flash("Amount must be positive.", "danger")
        elif not from_card or not to_card:
            flash("Card not found.", "danger")
        elif from_card_num == to_card_num:
            flash("Choose two different cards for exchange.", "warning")
        elif from_card['currency'] == to_card['currency']:
            flash("Cannot exchange the same currency.", "warning")
        elif from_card['balance'] < amount:
            flash(f"Insufficient {from_card['currency']} balance.", "danger")
        else:
            # 3. Calculate Exchange
            key = f"{from_card['currency']}_{to_card['currency']}"
            rate = rates.get(key)
            
            if not rate:
                flash("Exchange pair not supported.", "danger")
            else:
                final_amount = round(amount * rate, 2)
                
                # 4. Update Balances (Deduct From Card, Add To Card)
                conn.execute(
                    "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
                    (from_card_num,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO card_balances (card_number, amount) VALUES (?, 0)",
                    (to_card_num,),
                )
                conn.execute(
                    "UPDATE card_balances SET amount = amount - ? WHERE card_number=?",
                    (amount, from_card_num),
                )
                conn.execute(
                    "UPDATE card_balances SET amount = amount + ? WHERE card_number=?",
                    (final_amount, to_card_num),
                )
                
                # 5. Record Transaction
                note = f"FX: {amount} {from_card['currency']} -> {final_amount} {to_card['currency']}"
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Log both legs for clarity
                conn.execute("INSERT INTO transactions (account_id, timestamp, type, currency, amount, note) VALUES (?, ?, ?, ?, ?, ?)",
                             (uid, timestamp, "EXCHANGE_OUT", from_card['currency'], -amount, note))
                conn.execute("INSERT INTO transactions (account_id, timestamp, type, currency, amount, note) VALUES (?, ?, ?, ?, ?, ?)",
                             (uid, timestamp, "EXCHANGE_IN", to_card['currency'], final_amount, note))
                
                conn.commit()
                flash(
                    f"Success! Converted {amount} {from_card['currency']} to {final_amount} {to_card['currency']}.",
                    "success",
                )
                return redirect(url_for('dashboard'))

    conn.close()
    return render_template('exchange.html', cards=cards, rates=rates)

@app.route('/generate_qr/<card_number>')
def generate_qr(card_number):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    # Generate QR Code
    img = qrcode.make(card_number)
    
    # Save to memory buffer (no need to save file to disk)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    check_and_update_db_schema()
    app.run(debug=True, host='0.0.0.0', port=5000)
