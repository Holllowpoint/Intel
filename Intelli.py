import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime, timezone, timedelta
import traceback
import csv
import hashlib
import base64
import secrets
import threading
import re

# Password hashing utilities
def _hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2."""
    salt = secrets.token_bytes(32)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
    return f"{salt_b64}${hash_b64}"

def _verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash."""
    try:
        salt_b64, hash_b64 = stored.split('$', 1)
        salt = base64.b64decode(salt_b64)
        hash_bytes = base64.b64decode(hash_b64)
        test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return secrets.compare_digest(hash_bytes, test_hash)
    except Exception:
        return False

def _is_hashed_password(password: str) -> bool:
    """Check if a password is already hashed (contains $ separator)."""
    return '$' in password and len(password.split('$')) == 2

class ProgressSpinner:
    """Animated progress spinner for AI operations."""
    def __init__(self, parent, title="Processing..."):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("300x150")
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center the window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (300 // 2)
        y = (self.window.winfo_screenheight() // 2) - (150 // 2)
        self.window.geometry(f"300x150+{x}+{y}")
        
        # Create canvas for spinner
        self.canvas = tk.Canvas(self.window, width=60, height=60, bg='white')
        self.canvas.pack(pady=20)
        
        # Label
        ttk.Label(self.window, text=title, font=('Helvetica', 12)).pack()
        
        # Animation variables
        self.angle = 0
        self.arc_id = None
        self.animate()
    
    def animate(self):
        """Animate the spinner."""
        if self.window.winfo_exists():
            self.canvas.delete("all")
            # Draw rotating arc
            self.canvas.create_arc(10, 10, 50, 50, start=self.angle, extent=270, 
                                 outline='blue', width=3, style='arc')
            self.angle = (self.angle + 10) % 360
            self.window.after(50, self.animate)
    
    def destroy(self):
        """Close the spinner window."""
        if self.window.winfo_exists():
            self.window.destroy()

# Optional AI integration: if OPENAI_API_KEY present and openai installed, will call API.
# Otherwise returns canned responses.
def ai_query(prompt: str, context: str = "") -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return "AI companion (offline): I can't reach the remote AI. Try setting OPENAI_API_KEY to enable real responses.\n\nContext provided:\n" + (context or "(none)") + "\n\nYour question: " + prompt
    try:
        import openai

        openai.api_key = key
        messages = [
            {"role": "system", "content": "You are an educational assistant helping with syllabus items and scheduling. Be concise in your responses."},
        ]
        if context:
            messages.append({"role": "system", "content": "Context (Syllabus):\n" + context})
        messages.append({"role": "user", "content": prompt})
        resp = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=messages, max_tokens=200)
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"AI companion error: {e}"


def _parse_date_time(date_text: str, time_text: str):
    """Enhanced date/time parsing with natural language support."""
    date_text = (date_text or "").strip()
    time_text = (time_text or "").strip()
    if not date_text:
        return None, None

    # Month name mappings
    month_names = {
        'january': 1, 'jan': 1,
        'february': 2, 'feb': 2,
        'march': 3, 'mar': 3,
        'april': 4, 'apr': 4,
        'may': 5,
        'june': 6, 'jun': 6,
        'july': 7, 'jul': 7,
        'august': 8, 'aug': 8,
        'september': 9, 'sep': 9, 'sept': 9,
        'october': 10, 'oct': 10,
        'november': 11, 'nov': 11,
        'december': 12, 'dec': 12
    }

    # Weekday mappings
    weekdays = {
        'monday': 0, 'mon': 0,
        'tuesday': 1, 'tue': 1, 'tues': 1,
        'wednesday': 2, 'wed': 2,
        'thursday': 3, 'thu': 3, 'thur': 3, 'thurs': 3,
        'friday': 4, 'fri': 4,
        'saturday': 5, 'sat': 5,
        'sunday': 6, 'sun': 6
    }

    def strip_ordinals(text):
        """Remove ordinal suffixes like 1st, 2nd, 3rd, 21st, etc."""
        return re.sub(r'(\d+)(st|nd|rd|th)', r'\1', text)

    def parse_relative_date(text):
        """Parse relative dates like 'today', 'tomorrow', 'yesterday'."""
        text_lower = text.lower().strip()
        today = datetime.now().date()
        
        if text_lower == 'today':
            return today
        elif text_lower == 'tomorrow':
            return today + timedelta(days=1)
        elif text_lower == 'yesterday':
            return today - timedelta(days=1)
        elif text_lower.startswith('in '):
            # Parse "in X days/weeks/months"
            match = re.match(r'in (\d+) (day|week|month)s?', text_lower)
            if match:
                amount = int(match.group(1))
                unit = match.group(2)
                if unit == 'day':
                    return today + timedelta(days=amount)
                elif unit == 'week':
                    return today + timedelta(weeks=amount)
                elif unit == 'month':
                    # Approximate month as 30 days
                    return today + timedelta(days=amount * 30)
        elif text_lower.endswith(' from now'):
            # Parse "X days from now"
            match = re.match(r'(\d+) (day|week|month)s? from now', text_lower)
            if match:
                amount = int(match.group(1))
                unit = match.group(2)
                if unit == 'day':
                    return today + timedelta(days=amount)
                elif unit == 'week':
                    return today + timedelta(weeks=amount)
                elif unit == 'month':
                    return today + timedelta(days=amount * 30)
        elif text_lower in weekdays:
            # Parse weekday names
            target_weekday = weekdays[text_lower]
            current_weekday = today.weekday()
            days_ahead = target_weekday - current_weekday
            if days_ahead <= 0:  # Target day already passed this week
                days_ahead += 7
            return today + timedelta(days=days_ahead)
        elif text_lower.startswith('next '):
            # Parse "next Monday", etc.
            weekday_name = text_lower[5:].strip()
            if weekday_name in weekdays:
                target_weekday = weekdays[weekday_name]
                current_weekday = today.weekday()
                days_ahead = target_weekday - current_weekday
                if days_ahead <= 0:
                    days_ahead += 7
                return today + timedelta(days=days_ahead + 7)  # Next week
        elif text_lower.startswith('this '):
            # Parse "this Friday", etc.
            weekday_name = text_lower[5:].strip()
            if weekday_name in weekdays:
                target_weekday = weekdays[weekday_name]
                current_weekday = today.weekday()
                days_ahead = target_weekday - current_weekday
                if days_ahead < 0:  # Target day already passed this week
                    days_ahead += 7
                return today + timedelta(days=days_ahead)
        
        return None

    def parse_natural_date(text):
        """Parse natural language date formats."""
        text = strip_ordinals(text)
        text_lower = text.lower()
        
        # Try relative dates first
        relative_date = parse_relative_date(text)
        if relative_date:
            return relative_date
        
        # Try month name formats
        for month_name, month_num in month_names.items():
            if month_name in text_lower:
                # Extract day and year using regex
                patterns = [
                    r'(\d{1,2})\s+' + month_name + r'\s+(\d{4})',  # "12 October 2025"
                    month_name + r'\s+(\d{1,2})\s+(\d{4})',        # "October 12 2025"
                    r'(\d{1,2})\s+' + month_name + r'\s+(\d{2})',  # "12 Oct 25"
                    month_name + r'\s+(\d{1,2})\s+(\d{2})',        # "Oct 12 25"
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, text_lower)
                    if match:
                        groups = match.groups()
                        if len(groups) == 2:
                            try:
                                if pattern.startswith(r'(\d'):
                                    day = int(groups[0])
                                    year = int(groups[1])
                                else:
                                    day = int(groups[0])
                                    year = int(groups[1])
                                
                                # Handle 2-digit years
                                if year < 100:
                                    year += 2000 if year < 50 else 1900
                                
                                return datetime(year, month_num, day).date()
                            except ValueError:
                                continue
        
        return None

    # Try natural language parsing first
    dt_date = parse_natural_date(date_text)
    
    # Fall back to strict formats if natural parsing fails
    if not dt_date:
        date_formats = ["%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y"]
        for fmt in date_formats:
            try:
                dt_date = datetime.strptime(date_text, fmt).date()
                break
            except Exception:
                continue
    
    if not dt_date:
        raise ValueError("Date not in supported formats. Try: YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY, '12 October 2025', 'today', 'tomorrow', 'Monday', etc.")

    if not time_text:
        return dt_date.isoformat(), None

    dt_time = None
    time_formats = ["%H:%M", "%H%M", "%I:%M%p", "%I%p", "%I:%M %p", "%I %p"]
    for fmt in time_formats:
        try:
            dt_time = datetime.strptime(time_text, fmt).time()
            break
        except Exception:
            continue
    if not dt_time:
        raise ValueError("Time not in supported formats (24h HH:MM or 12h HH:MM AM/PM)")

    return dt_date.isoformat(), dt_time.strftime("%H:%M")


def _format_local_from_utc_iso(iso_text: str):
    if not iso_text:
        return None
    s = iso_text.strip()
    if s.endswith("Z"):
        s = s[:-1]
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except Exception:
                dt = None
        if not dt:
            return iso_text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        local = dt.astimezone()
        return local.strftime("%b %d, %Y %I:%M %p")
    except Exception:
        return dt.strftime("%Y-%m-%d %H:%M:%S")


def _format_date_time_local(date_iso: str, time_hm: str | None):
    if not date_iso:
        return ""
    try:
        if time_hm:
            dt = datetime.strptime(f"{date_iso} {time_hm}", "%Y-%m-%d %H:%M")
            return dt.strftime("%b %d, %Y %I:%M %p")
        else:
            dt = datetime.strptime(date_iso, "%Y-%m-%d")
            return dt.strftime("%b %d, %Y")
    except Exception:
        return f"{date_iso} {time_hm or ''}".strip()


class SyllabusDB:
    # Whitelist of allowed columns for update operations
    ALLOWED_COLUMNS = {
        "details", "date", "time", "status", "started_at", 
        "completed_at", "submission", "type", "subject"
    }
    
    def __init__(self, path=None):
        if path is None:
            base = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(base, "syllabus.db")
        self.path = path
        self.conn = sqlite3.connect(self.path, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        self.conn.row_factory = sqlite3.Row
        self._migrate_table()

    def _migrate_table(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS syllabus_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                details TEXT NOT NULL,
                date TEXT,
                time TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                type TEXT DEFAULT 'topic',
                subject TEXT,
                submission TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

        # Add new columns if missing
        cur.execute("PRAGMA table_info(syllabus_items)")
        cols = {r["name"] for r in cur.fetchall()}
        add = []
        if "type" not in cols:
            add.append("ALTER TABLE syllabus_items ADD COLUMN type TEXT DEFAULT 'topic'")
        if "subject" not in cols:
            add.append("ALTER TABLE syllabus_items ADD COLUMN subject TEXT")
        if "submission" not in cols:
            add.append("ALTER TABLE syllabus_items ADD COLUMN submission TEXT")
        for stmt in add:
            try:
                cur.execute(stmt)
            except Exception:
                pass
        
        # Migrate existing plaintext passwords to hashed passwords
        try:
            cur.execute("SELECT id, email, password FROM users WHERE password NOT LIKE '%$%'")
            plaintext_users = cur.fetchall()
            for user in plaintext_users:
                hashed_password = _hash_password(user["password"])
                cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user["id"]))
        except Exception:
            pass  # Ignore migration errors
        
        self.conn.commit()

    def add_user(self, email, password, role):
        cur = self.conn.cursor()
        hashed_password = _hash_password(password)
        cur.execute("INSERT OR IGNORE INTO users (email, password, role) VALUES (?, ?, ?)", (email, hashed_password, role))
        self.conn.commit()

    def get_user(self, email, password):
        cur = self.conn.cursor()
        cur.execute("SELECT password, role FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if row:
            stored_password = row["password"]
            
            # Check if password is already hashed (contains $ separator)
            if _is_hashed_password(stored_password):
                # Verify hashed password
                if _verify_password(password, stored_password):
                    return row["role"]
            else:
                # Legacy plaintext password - verify directly and migrate
                if password == stored_password:
                    # Migrate to hashed password
                    hashed_password = _hash_password(password)
                    cur.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
                    self.conn.commit()
                    return row["role"]
        
        return None

    def add_item(self, details, date_iso, time_hm, item_type, subject):
        created = datetime.utcnow().isoformat() + "Z"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO syllabus_items (details, date, time, created_at, status, type, subject) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (details, date_iso, time_hm, created, "pending", item_type, subject),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_items(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM syllabus_items")
        return cur.fetchall()

    def get_item(self, item_id):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM syllabus_items WHERE id = ?", (item_id,))
        return cur.fetchone()

    def delete_item(self, item_id):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM syllabus_items WHERE id = ?", (item_id,))
        self.conn.commit()

    def update_item(self, item_id, **fields):
        if not fields:
            return
        
        # Validate column names against whitelist
        invalid_columns = set(fields.keys()) - self.ALLOWED_COLUMNS
        if invalid_columns:
            raise ValueError(f"Invalid column names: {', '.join(invalid_columns)}. Allowed: {', '.join(sorted(self.ALLOWED_COLUMNS))}")
        
        keys = ", ".join(f"{k} = ?" for k in fields.keys())
        vals = list(fields.values()) + [item_id]
        cur = self.conn.cursor()
        cur.execute(f"UPDATE syllabus_items SET {keys} WHERE id = ?", vals)
        self.conn.commit()

    def close(self):
        try:
            self.conn.commit()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


class EducationApp:
    def __init__(self, root):
        self.root = root
        self.db = SyllabusDB()
        self.role = None
        self.root.title("Education Platform")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10))
        self.style.configure('TEntry', font=('Helvetica', 10))
        self.style.configure('TCombobox', font=('Helvetica', 10))
        self.style.configure('TText', font=('Helvetica', 10))
        self._setup_geometry_and_zoom()
        self._build_login_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_quit)

    def _setup_geometry_and_zoom(self):
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            self.root.geometry(f"{int(sw*0.9)}x{int(sh*0.9)}+10+10")
            if os.name == "nt":
                self.root.state("zoomed")
            else:
                self.root.attributes("-zoomed", True)
        except Exception:
            pass

    def _build_login_ui(self):
        self.login_frm = ttk.Frame(self.root, padding=10)
        self.login_frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(self.login_frm, text="Email:").pack(anchor=tk.W)
        self.email_entry = ttk.Entry(self.login_frm)
        self.email_entry.pack(fill=tk.X, pady=5)
        ttk.Label(self.login_frm, text="Password:").pack(anchor=tk.W)
        self.pass_entry = ttk.Entry(self.login_frm, show="*")
        self.pass_entry.pack(fill=tk.X, pady=5)
        ttk.Label(self.login_frm, text="Role:").pack(anchor=tk.W)
        self.role_var = tk.StringVar()
        role_combo = ttk.Combobox(self.login_frm, textvariable=self.role_var, values=["Teacher", "Student"])
        role_combo.pack(fill=tk.X, pady=5)
        login_btn = ttk.Button(self.login_frm, text="Login", command=self._on_login)
        login_btn.pack(pady=5)
        register_btn = ttk.Button(self.login_frm, text="Register", command=self._on_register)
        register_btn.pack(pady=5)
        # Note: Google login would require OAuth, omitted for simplicity

    def _on_register(self):
        email = self.email_entry.get().strip()
        passw = self.pass_entry.get().strip()
        role = self.role_var.get()
        if email and passw and role:
            try:
                self.db.add_user(email, passw, role)
                
                # Clear the login/registration fields immediately
                self.email_entry.delete(0, tk.END)
                self.pass_entry.delete(0, tk.END)
                self.role_var.set("")
                
                # Show a small registration-complete window
                reg_win = tk.Toplevel(self.root)
                reg_win.title("Registration Successful")
                reg_win.geometry("300x150")
                reg_win.transient(self.root)
                reg_win.grab_set()
                
                ttk.Label(reg_win, text="Registration successful!\nYou can now login.", 
                         justify=tk.CENTER).pack(padx=20, pady=20)
                
                def _close_and_focus():
                    reg_win.destroy()
                    self.email_entry.focus_set()
                
                ttk.Button(reg_win, text="Continue to Login", command=_close_and_focus).pack(pady=10)
                
            except Exception as e:
                messagebox.showerror("Error", f"Unable to register user:\n{e}")
        else:
            messagebox.showerror("Error", "All fields required.")

    def _on_login(self):
        email = self.email_entry.get().strip()
        passw = self.pass_entry.get().strip()
        role = self.db.get_user(email, passw)
        if role:
            self.role = role.lower()
            self.login_frm.destroy()
            self._build_main_menu()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    def _build_main_menu(self):
        self.menu_frm = ttk.Frame(self.root, padding=10)
        self.menu_frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(self.menu_frm, text=f"Welcome, {self.role.capitalize()}").pack(anchor=tk.W, pady=10)
        syll_btn = ttk.Button(self.menu_frm, text="Intelli Syllabus Scheduler", command=self._launch_syllabus)
        syll_btn.pack(fill=tk.X, pady=5)
        ai_btn = ttk.Button(self.menu_frm, text="AI Companion", command=self._launch_ai_companion)
        ai_btn.pack(fill=tk.X, pady=5)
        export_btn = ttk.Button(self.menu_frm, text="Export Syllabus", command=self._export_syllabus)
        export_btn.pack(fill=tk.X, pady=5)
        cal_btn = ttk.Button(self.menu_frm, text="Sync Calendar (Export ICS)", command=self._export_ics)
        cal_btn.pack(fill=tk.X, pady=5)
        quit_btn = ttk.Button(self.menu_frm, text="Quit", command=self._on_quit)
        quit_btn.pack(fill=tk.X, pady=5)

    def _export_syllabus(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            items = self.db.list_items()
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=items[0].keys() if items else [])
                writer.writeheader()
                for item in items:
                    writer.writerow(dict(item))
            messagebox.showinfo("Exported", "Syllabus exported to CSV.")

    def _export_ics(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".ics", filetypes=[("ICS files", "*.ics")])
        if file_path:
            ics_content = "BEGIN:VCALENDAR\nVERSION:2.0\n"
            items = self.db.list_items()
            for item in items:
                if item['date']:
                    dt_str = datetime.fromisoformat(item['date']).strftime("%Y%m%d")
                    if item['time']:
                        dt_str += "T" + item['time'].replace(":", "") + "00"
                    ics_content += "BEGIN:VEVENT\n"
                    ics_content += f"SUMMARY:{item['details']}\n"
                    ics_content += f"DTSTART:{dt_str}\n"
                    ics_content += "END:VEVENT\n"
            ics_content += "END:VCALENDAR\n"
            with open(file_path, 'w') as f:
                f.write(ics_content)
            messagebox.showinfo("Exported", "Calendar exported to ICS.")

    def _launch_syllabus(self):
        self.menu_frm.destroy()
        self.syll_frm = ttk.Frame(self.root, padding=10)
        self.syll_frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(self.syll_frm, text="Syllabus Item Details (required):").pack(anchor=tk.W)
        self.details_text = tk.Text(self.syll_frm, height=20, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=False, padx=0, pady=(0, 10))

        dt_row = ttk.Frame(self.syll_frm)
        dt_row.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(dt_row, text="Date (required):").grid(row=0, column=0, sticky=tk.W)
        self.date_entry = ttk.Entry(dt_row)
        self.date_entry.grid(row=0, column=1, sticky=tk.W, padx=(5, 15))
        ttk.Label(dt_row, text="Time (optional):").grid(row=0, column=2, sticky=tk.W)
        self.time_entry = ttk.Entry(dt_row)
        self.time_entry.grid(row=0, column=3, sticky=tk.W, padx=(5, 15))

        type_row = ttk.Frame(self.syll_frm)
        type_row.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(type_row, text="Type:").grid(row=0, column=0, sticky=tk.W)
        self.type_var = tk.StringVar(value="topic")
        type_combo = ttk.Combobox(type_row, textvariable=self.type_var, values=["topic", "assignment", "sba_guide"])
        type_combo.grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(type_row, text="Subject:").grid(row=0, column=2, sticky=tk.W)
        self.subject_entry = ttk.Entry(type_row)
        self.subject_entry.grid(row=0, column=3, sticky=tk.W, padx=5)

        btn_row = ttk.Frame(self.syll_frm)
        btn_row.pack(fill=tk.X)
        if self.role == "teacher":
            add_btn = ttk.Button(btn_row, text="Add Item", command=self._on_add_item)
            add_btn.pack(side=tk.LEFT, padx=(0, 10))
            gen_btn = ttk.Button(btn_row, text="Generate with AI", command=self._on_generate_ai)
            gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        view_btn = ttk.Button(btn_row, text="View Syllabus", command=self._open_view_syllabus)
        view_btn.pack(side=tk.LEFT, padx=(0, 10))
        back_btn = ttk.Button(btn_row, text="Back", command=self._back_to_menu_from_syll)
        back_btn.pack(side=tk.LEFT, padx=(0, 10))
        quit_btn = ttk.Button(btn_row, text="Quit", command=self._on_quit)
        quit_btn.pack(side=tk.LEFT)

    def _on_add_item(self):
        details = self.details_text.get("1.0", tk.END).strip()
        if not details:
            messagebox.showwarning("Validation", "Syllabus item details are required.")
            return
        date_in = self.date_entry.get().strip()
        time_in = self.time_entry.get().strip()
        item_type = self.type_var.get()
        subject = self.subject_entry.get().strip()

        if not date_in:
            messagebox.showwarning("Validation", "Date is required.")
            return

        try:
            date_iso, time_hm = _parse_date_time(date_in, time_in)
        except Exception as e:
            messagebox.showerror("Invalid date/time", str(e))
            return

        try:
            self.db.add_item(details, date_iso, time_hm, item_type, subject)
        except Exception as e:
            messagebox.showerror("Database error", f"Unable to save item:\n{e}")
            return

        self.details_text.delete("1.0", tk.END)
        self.date_entry.delete(0, tk.END)
        self.time_entry.delete(0, tk.END)
        self.subject_entry.delete(0, tk.END)
        messagebox.showinfo("Saved", "Syllabus item added successfully.")

    def _on_generate_ai(self):
        ai_prompt = simpledialog.askstring("AI Generate", "Describe the syllabus item to generate:")
        if ai_prompt:
            # Show progress spinner
            spinner = ProgressSpinner(self.root, "Generating with AI...")
            
            def ai_worker():
                try:
                    context = self._get_syllabus_context()
                    response = ai_query("Generate a concise detailed syllabus item based on: " + ai_prompt, context)
                    # Schedule UI update on main thread
                    self.root.after(0, lambda: self._handle_ai_response(response, spinner))
                except Exception as ex:
                    self.root.after(0, lambda: self._handle_ai_error(str(ex), spinner))
            
            # Start AI query in background thread
            thread = threading.Thread(target=ai_worker, daemon=True)
            thread.start()
    
    def _handle_ai_response(self, response, spinner):
        """Handle successful AI response."""
        spinner.destroy()
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", response)
    
    def _handle_ai_error(self, error_msg, spinner):
        """Handle AI error."""
        spinner.destroy()
        messagebox.showerror("AI Error", f"Failed to generate content:\n{error_msg}")

    def _open_view_syllabus(self):
        self._refresh_syllabus_popup()

    def _refresh_syllabus_popup(self):
        try:
            if hasattr(self, "_popup") and self._popup.winfo_exists():
                self._popup.destroy()
        except Exception:
            pass

        self._popup = tk.Toplevel(self.root)
        self._popup.title("Syllabus")
        self._popup.protocol("WM_DELETE_WINDOW", self._popup.destroy)

        container = ttk.Frame(self._popup)
        container.pack(fill=tk.BOTH, expand=True)

        search_row = ttk.Frame(container, padding=(6, 6))
        search_row.pack(fill=tk.X)
        ttk.Label(search_row, text="Search:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_row, textvariable=search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        canvas_container = ttk.Frame(container)
        canvas_container.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(canvas_container)
        scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)

        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_configure)

        all_items = list(self.db.list_items())

        def sort_key(row):
            d = row["date"]
            t = row["time"]
            if d:
                try:
                    dt_str = d + (" " + t if t else "")
                    fmt = "%Y-%m-%d %H:%M" if t else "%Y-%m-%d"
                    dt = datetime.strptime(dt_str, fmt)
                    return (0, dt)
                except Exception:
                    return (0, datetime.max)
            else:
                return (1, row["id"])

        all_items.sort(key=sort_key)

        def build_rows(filter_text: str = ""):
            for child in inner.winfo_children():
                child.destroy()

            filtered = []
            ft = (filter_text or "").strip().lower()
            for item in all_items:
                if not ft or ft in (item["details"] or "").lower() or ft in (item["date"] or "").lower() or ft in (item["time"] or "").lower() or ft in (item["status"] or "").lower() or ft in (item["type"] or "").lower() or ft in (item["subject"] or "").lower():
                    filtered.append(item)

            for idx, item in enumerate(filtered):
                frame = ttk.Frame(inner, relief=tk.RIDGE, padding=6)
                frame.grid(row=idx, column=0, sticky="ew", padx=5, pady=5)
                frame.columnconfigure(0, weight=1)

                desc_widget = tk.Text(frame, height=4, wrap=tk.WORD)
                desc_widget.insert("1.0", f"{item['subject']} - {item['type'].capitalize()}: {item['details']}")
                desc_widget.configure(state="disabled", background=frame.cget("background"), relief=tk.FLAT)
                desc_widget.grid(row=0, column=0, sticky="we")

                def make_view_full(trow):
                    def _view(event=None):
                        vp = tk.Toplevel(self._popup)
                        vp.title("Syllabus Item Detail")
                        vp.geometry("700x400")
                        txt = tk.Text(vp, wrap=tk.WORD)
                        txt.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
                        txt.insert("1.0", f"{trow['subject']} - {trow['type'].capitalize()}: {trow['details']}")
                        txt.configure(state="disabled")
                        meta_lbl = ttk.Label(vp, text=self._meta_text(trow), foreground="gray")
                        meta_lbl.pack(anchor="w", padx=6, pady=(0, 6))
                        action_row = ttk.Frame(vp)
                        action_row.pack(fill=tk.X, padx=6, pady=6)
                        if self.role == "teacher":
                            def delete_and_close():
                                if messagebox.askyesno("Delete Item", "Delete this syllabus item?"):
                                    try:
                                        self.db.delete_item(trow["id"])
                                        vp.destroy()
                                        self._refresh_syllabus_popup()
                                    except Exception as e:
                                        messagebox.showerror("Error", f"Unable to delete item:\n{e}")
                            del_btn = ttk.Button(action_row, text="Delete", command=delete_and_close)
                            del_btn.pack(side=tk.LEFT, padx=(0, 6))
                            def edit_and_refresh():
                                new = simpledialog.askstring("Edit", "New details:", initialvalue=trow["details"], parent=vp)
                                if new is not None:
                                    try:
                                        self.db.update_item(trow["id"], details=new)
                                        vp.destroy()
                                        self._refresh_syllabus_popup()
                                    except Exception as e:
                                        messagebox.showerror("Error", f"Unable to update item:\n{e}")
                            edit_btn = ttk.Button(action_row, text="Edit", command=edit_and_refresh)
                            edit_btn.pack(side=tk.LEFT)
                        if self.role == "student" and trow["type"] == "assignment" and not trow["submission"]:
                            def submit_and_close():
                                sub = simpledialog.askstring("Submit", "Your submission:", parent=vp)
                                if sub:
                                    try:
                                        self.db.update_item(trow["id"], submission=sub)
                                        vp.destroy()
                                        self._refresh_syllabus_popup()
                                    except Exception as e:
                                        messagebox.showerror("Error", f"Unable to submit:\n{e}")
                            sub_btn = ttk.Button(action_row, text="Submit Assignment", command=submit_and_close)
                            sub_btn.pack(side=tk.LEFT)
                        if trow["submission"]:
                            sub_lbl = ttk.Label(vp, text=f"Submission: {trow['submission']}", foreground="blue")
                            sub_lbl.pack(anchor="w", padx=6, pady=6)
                    return _view

                desc_widget.bind("<Double-Button-1>", make_view_full(item))

                meta_parts = []
                if item["date"]:
                    meta_parts.append(f"Scheduled: {_format_date_time_local(item['date'], item['time'])}")
                if item["created_at"]:
                    meta_parts.append(f"Created: {_format_local_from_utc_iso(item['created_at'])}")
                if item["started_at"]:
                    meta_parts.append(f"Started: {_format_local_from_utc_iso(item['started_at'])}")
                if item["completed_at"]:
                    meta_parts.append(f"Completed: {_format_local_from_utc_iso(item['completed_at'])}")
                meta_label = ttk.Label(frame, text=" | ".join(meta_parts), foreground="gray")
                meta_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

                btns = ttk.Frame(frame)
                btns.grid(row=0, column=1, rowspan=2, sticky="e", padx=(10, 0))
                start_btn = ttk.Button(btns, text="Mark Started")
                complete_btn = ttk.Button(btns, text="Mark Completed")
                ai_btn = ttk.Button(btns, text="Ask AI")

                def make_start(iid, s_btn, c_btn, meta_widget):
                    def _start():
                        started_at = datetime.utcnow().isoformat() + "Z"
                        try:
                            self.db.update_item(iid, status="started", started_at=started_at)
                            s_btn.state(["disabled"])
                            c_btn.state(["!disabled"])
                            trow = self.db.get_item(iid)
                            meta_widget.config(text=self._meta_text(trow))
                        except Exception as e:
                            messagebox.showerror("Error", f"Unable to mark started:\n{e}")
                    return _start

                def make_complete(iid, s_btn, c_btn, meta_widget):
                    def _complete():
                        completed_at = datetime.utcnow().isoformat() + "Z"
                        try:
                            self.db.update_item(iid, status="completed", completed_at=completed_at)
                            s_btn.state(["!disabled"])
                            c_btn.state(["disabled"])
                            trow = self.db.get_item(iid)
                            meta_widget.config(text=self._meta_text(trow))
                        except Exception as e:
                            messagebox.showerror("Error", f"Unable to mark completed:\n{e}")
                    return _complete

                def make_ask_ai(i_details, i_subject):
                    def _ask():
                        question = simpledialog.askstring("Ask AI", "Your question about this topic:")
                        if question:
                            # Show progress spinner
                            spinner = ProgressSpinner(self.root, "Asking AI...")
                            
                            def ai_worker():
                                try:
                                    context = self._get_syllabus_context()
                                    response = ai_query(question + "\n\nTopic: " + i_subject + " - " + i_details, context)
                                    # Schedule UI update on main thread
                                    self.root.after(0, lambda: self._handle_ask_ai_response(response, spinner))
                                except Exception as ex:
                                    self.root.after(0, lambda: self._handle_ask_ai_error(str(ex), spinner))
                            
                            # Start AI query in background thread
                            thread = threading.Thread(target=ai_worker, daemon=True)
                            thread.start()
                    
                    def _handle_ask_ai_response(response, spinner):
                        """Handle successful AI response for ask AI."""
                        spinner.destroy()
                        messagebox.showinfo("AI Response", response)
                    
                    def _handle_ask_ai_error(error_msg, spinner):
                        """Handle AI error for ask AI."""
                        spinner.destroy()
                        messagebox.showerror("AI Error", f"Failed to get AI response:\n{error_msg}")
                    
                    return _ask

                status = item["status"] or "pending"
                if status == "started":
                    start_btn.state(["disabled"])
                    complete_btn.state(["!disabled"])
                elif status == "completed":
                    start_btn.state(["!disabled"])
                    complete_btn.state(["disabled"])
                else:
                    start_btn.state(["!disabled"])
                    complete_btn.state(["disabled"])

                start_btn.config(command=make_start(item["id"], start_btn, complete_btn, meta_label))
                complete_btn.config(command=make_complete(item["id"], start_btn, complete_btn, meta_label))
                ai_btn.config(command=make_ask_ai(item["details"], item["subject"]))

                if self.role == "teacher":
                    start_btn.pack(side=tk.LEFT, padx=(0, 4))
                    complete_btn.pack(side=tk.LEFT, padx=(0, 4))
                ai_btn.pack(side=tk.LEFT)

        build_rows("")

        def on_search_var(*args):
            build_rows(search_var.get())
        search_var.trace_add("write", on_search_var)

        def _resize_canvas(event):
            try:
                canvas.itemconfig(inner_id, width=event.width)
            except Exception:
                pass
        canvas.bind("<Configure>", _resize_canvas)

    def _meta_text(self, item_row):
        parts = []
        if item_row["date"]:
            parts.append(f"Scheduled: {_format_date_time_local(item_row['date'], item_row['time'])}")
        if item_row["created_at"]:
            parts.append(f"Created: {_format_local_from_utc_iso(item_row['created_at'])}")
        if item_row["started_at"]:
            parts.append(f"Started: {_format_local_from_utc_iso(item_row['started_at'])}")
        if item_row["completed_at"]:
            parts.append(f"Completed: {_format_local_from_utc_iso(item_row['completed_at'])}")
        return " | ".join(parts)

    def _back_to_menu_from_syll(self):
        self.syll_frm.destroy()
        self._build_main_menu()

    def _launch_ai_companion(self):
        ai_win = tk.Toplevel(self.root)
        ai_win.title("AI Companion")
        ttk.Label(ai_win, text="Ask the AI (for topics, assignments, etc.):").pack(anchor=tk.W, padx=10, pady=5)
        prompt_text = tk.Text(ai_win, height=5, wrap=tk.WORD)
        prompt_text.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        def _query():
            prompt = prompt_text.get("1.0", tk.END).strip()
            if prompt:
                # Disable button and show processing state
                query_btn.config(text="Processing...", state="disabled")
                
                def ai_worker():
                    try:
                        context = self._get_syllabus_context()
                        response = ai_query(prompt, context)
                        # Schedule UI update on main thread
                        self.root.after(0, lambda: self._handle_companion_response(response, query_btn))
                    except Exception as ex:
                        self.root.after(0, lambda: self._handle_companion_error(str(ex), query_btn))
                
                # Start AI query in background thread
                thread = threading.Thread(target=ai_worker, daemon=True)
                thread.start()
        
        def _handle_companion_response(response, btn):
            """Handle successful AI companion response."""
            btn.config(text="Query", state="normal")
            resp_text.delete("1.0", tk.END)
            resp_text.insert("1.0", response)
        
        def _handle_companion_error(error_msg, btn):
            """Handle AI companion error."""
            btn.config(text="Query", state="normal")
            resp_text.delete("1.0", tk.END)
            resp_text.insert("1.0", f"AI Error: {error_msg}")
        query_btn = ttk.Button(ai_win, text="Query", command=_query)
        query_btn.pack(pady=5)
        resp_text = tk.Text(ai_win, height=15, wrap=tk.WORD)
        resp_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _get_syllabus_context(self):
        items = self.db.list_items()
        ctx = "Syllabus:\n"
        for item in items:
            ctx += f"{item['subject']} - {item['type']}: {_format_date_time_local(item['date'], item['time'])}: {item['details']}\n"
        return ctx

    def _on_quit(self):
        try:
            self.db.close()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = EducationApp(root)
        root.mainloop()
    except Exception:
        traceback.print_exc()