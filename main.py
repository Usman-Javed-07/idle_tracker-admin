import os
import sys
import traceback
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from plyer import notification

# --- UI: CustomTkinter ---
import customtkinter as ctk

from backend.models import (
    init_tables, list_users, fetch_unnotified_inactive_events, mark_event_notified,
    fetch_user_inactive_history, fetch_screenshots_for_user, fetch_recordings_for_user,
    list_admin_emails,
    admin_update_user, admin_delete_user, fetch_overtime_sum, get_user_by_id,
)
from backend.auth import login, admin_create_user, hash_password
from backend.config import ADMIN_BOOTSTRAP
from backend.notify import send_email

try:
    from backend.config import ALERT_RECIPIENTS
except Exception:
    ALERT_RECIPIENTS = []

REFRESH_MS = 2000  # poll db every 2s

# ---- Branding / Colors ----
APP_NAME = "Mars Capital"
APP_AUMID = "Mars Capital"
APP_ICON = os.path.join(os.getcwd(), "assets", "mars.ico")
if not os.path.isfile(APP_ICON):
    APP_ICON = None

# Theme
ctk.set_appearance_mode("System")       # "Dark" | "Light" | "System"
ctk.set_default_color_theme("blue")     # "blue" | "green" | "dark-blue"

APP_BG = ("#f5f7fb", "#0f1115")         # main window background
BAR_BG = ("#ffffff", "#151922")         # navbar & footer
SIDEBAR_BG = ("#eef2f7", "#0f1624")     # sidebar bg (different)
CARD_BG = ("#ffffff", "#1b2030")
MUTED_TX = ("#6b7280", "#9aa4b2")

TOTAL_ACTIVE_COLOR = "#22c55e"
TOTAL_INACTIVE_COLOR = "#ef4444"
TOTAL_OVERTIME_COLOR = "#3b82f6"

INACTIVE_ROW_BG = "#fee2e2"  # light red row bg for inactive events

# Set AppUserModelID (Windows) so toasts won’t say "Python"
if sys.platform.startswith("win"):
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_AUMID)
    except Exception:
        pass


def admin_notify(title, message, timeout=5):
    try:
        kw = {"title": title, "message": message, "timeout": timeout, "app_name": APP_NAME}
        if APP_ICON:
            kw["app_icon"] = APP_ICON
        notification.notify(**kw)
    except Exception:
        pass


def seconds_to_hhmmss(sec):
    if sec is None:
        return "00:00:00"
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"


# =============================
# Main Application (CustomTk)
# =============================
class AdminApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Admin Dashboard - Idle Tracker")
        self.geometry("1220x780")
        self.minsize(1100, 720)
        self.configure(fg_color=APP_BG)
        init_tables()

        if APP_ICON and sys.platform.startswith("win"):
            try:
                self.iconbitmap(APP_ICON)
            except Exception:
                pass

        self.admin_user = None
        self.frames = {}
        for F in (AdminLoginFrame, AdminDashboardFrame):
            frame = F(self)
            self.frames[F.__name__] = frame

        self.show_frame("AdminLoginFrame")

        self._poll_job = None
        self.auto_refresh_enabled = False  # enable after login

        # center on screen
        self.after(10, self._center_on_screen)

    def _center_on_screen(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw // 2) - (w // 2)
        y = (sh // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def show_frame(self, name):
        for f in self.frames.values():
            f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def on_admin_logged_in(self, admin_user):
        if not admin_user or admin_user.get("role") != "admin":
            messagebox.showwarning("Access denied", "Admin only.")
            return
        self.admin_user = admin_user
        dash = self.frames["AdminDashboardFrame"]
        dash.set_admin_name(self.admin_user.get("name") or self.admin_user.get("username") or "Admin")
        self.show_frame("AdminDashboardFrame")
        self.auto_refresh_enabled = True
        self._schedule_poll()

    def logout(self):
        self.auto_refresh_enabled = False
        self.admin_user = None
        self.show_frame("AdminLoginFrame")

    def _schedule_poll(self):
        if self._poll_job:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
        self._poll_job = self.after(REFRESH_MS, self._poll_new_inactive)

    def _poll_new_inactive(self):
        if not self.auto_refresh_enabled:
            return self._schedule_poll()

        updated_users = None
        try:
            rows = fetch_unnotified_inactive_events()
            for r in rows:
                msg = (f"{r['name']} (@{r['username']}, {r['email']}, {r['department']}) "
                       f"is INACTIVE at {r['occurred_at']} "
                       f"(active streak: {seconds_to_hhmmss(r['active_duration_seconds'])}).")
                try:
                    notification.notify(title="User Inactive", message=msg, timeout=4, app_name=APP_NAME)
                except Exception:
                    pass
                try:
                    recipients = {r.get("email")}
                    recipients.update(e for e in list_admin_emails() if e)
                    if ADMIN_BOOTSTRAP.get("email"):
                        recipients.add(ADMIN_BOOTSTRAP["email"])
                    recipients.update(ALERT_RECIPIENTS)
                    recipients.discard(None)
                    if recipients:
                        send_email(list(recipients),
                                   subject=f"[IdleTracker] {r['username']} inactive",
                                   body=msg)
                except Exception:
                    pass

                mark_event_notified(r["id"])

            dash = self.frames["AdminDashboardFrame"]
            text = dash.search_var.get().strip() or None
            st = dash.status_var.get().strip()
            status = None if st == "Any" else st
            updated_users = list_users(search=text, status=status, hide_admin=True)
        except Exception as e:
            print("Poll error:", e)

        if updated_users is not None:
            self.frames["AdminDashboardFrame"].apply_user_delta(updated_users)

        self._schedule_poll()


# =============================
# Login Frame (CustomTk)
# =============================
class AdminLoginFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, corner_radius=0, fg_color=APP_BG)

        card = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        card.pack(expand=True, fill="x", padx=32, pady=32)

        ctk.CTkLabel(card, text="Admin Login", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(18, 6))

        self.login_id = tk.StringVar(value=ADMIN_BOOTSTRAP.get("email", ""))
        self.login_pwd = tk.StringVar(value=ADMIN_BOOTSTRAP.get("password", ""))

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=20, pady=8)

        ctk.CTkLabel(form, text="Username or Email").pack(anchor="w")
        self.e_user = ctk.CTkEntry(form, textvariable=self.login_id, placeholder_text="admin@example.com", height=40)
        self.e_user.pack(fill="x", pady=(2, 8))

        ctk.CTkLabel(form, text="Password").pack(anchor="w")
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", pady=(2, 12))
        self.e_pwd = ctk.CTkEntry(row, textvariable=self.login_pwd, show="•", placeholder_text="••••••••", height=40)
        self.e_pwd.pack(side="left", fill="x", expand=True)

        def toggle_pwd():
            self.e_pwd.configure(show="" if self.e_pwd.cget("show") == "•" else "•")
            btn_toggle.configure(text=("Hide" if self.e_pwd.cget("show") == "" else "Show"))
        btn_toggle = ctk.CTkButton(row, text="Show", width=72, command=toggle_pwd)
        btn_toggle.pack(side="left", padx=(8, 0))

        ctk.CTkButton(card, text="Login", height=42, command=self.do_login).pack(pady=(6, 18), padx=20, fill="x")

        # Footer brand
        foot = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        foot.pack(side="bottom", fill="x")
        ctk.CTkLabel(foot, text="Mars Capital", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(foot, text="Lead with discipline. Excellence follows.", text_color=MUTED_TX).pack(side="right", padx=12, pady=6)

    def do_login(self):
        try:
            admin = login(self.login_id.get().strip(), self.login_pwd.get().strip())
            if not admin:
                messagebox.showerror("Login failed", "Invalid credentials")
                return
            self.master.on_admin_logged_in(admin)
        except Exception as e:
            messagebox.showerror("Error", str(e))


# =============================
# Dashboard (CustomTk)
# =============================
class AdminDashboardFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, corner_radius=0, fg_color=APP_BG)

        self.admin_name = tk.StringVar(value="Admin")

        # ===== NAVBAR =====
        navbar = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        navbar.pack(side="top", fill="x")

        left = ctk.CTkFrame(navbar, fg_color="transparent")
        left.pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(left, text="Mars Capital", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w")

        middle = ctk.CTkFrame(navbar, fg_color="transparent")
        middle.pack(side="left", padx=16, pady=8)
        ctk.CTkLabel(middle, textvariable=self.admin_name, text_color=MUTED_TX).pack(anchor="w")

        right = ctk.CTkFrame(navbar, fg_color="transparent")
        right.pack(side="right", padx=12, pady=8)
        ctk.CTkButton(right, text="Add User", width=100, command=self.open_create_user).pack(side="left", padx=(0,8))
        ctk.CTkButton(right, text="Logout", width=90, command=self.master.logout).pack(side="left")

        # ===== TOTALS STRIP =====
        totals = ctk.CTkFrame(self, fg_color="transparent")
        totals.pack(fill="x", padx=12, pady=(8, 6))

        def make_total(parent, label, color):
            card = ctk.CTkFrame(parent, corner_radius=12, fg_color=CARD_BG)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            ctk.CTkLabel(inner, text=label, text_color=MUTED_TX).pack(anchor="w")
            value_sv = tk.StringVar(value="0")
            lbl = ctk.CTkLabel(inner, textvariable=value_sv, font=ctk.CTkFont(size=18, weight="bold"))
            lbl.configure(text_color=color)
            lbl.pack(anchor="w")
            return card, value_sv

        totals_row = ctk.CTkFrame(totals, fg_color="transparent")
        totals_row.pack(fill="x")

        card_a, self.total_active_sv = make_total(totals_row, "Active Users", TOTAL_ACTIVE_COLOR)
        card_i, self.total_inactive_sv = make_total(totals_row, "Inactive Users", TOTAL_INACTIVE_COLOR)
        card_o, self.total_overtime_sv = make_total(totals_row, "Overtime (today)", TOTAL_OVERTIME_COLOR)

        card_a.pack(side="left", fill="x", expand=True, padx=(0,6))
        card_i.pack(side="left", fill="x", expand=True, padx=6)
        card_o.pack(side="left", fill="x", expand=True, padx=(6,0))

        # ===== BODY LAYOUT =====
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=(6, 0))

        # Sidebar (filters)
        sidebar = ctk.CTkFrame(body, width=280, corner_radius=12, fg_color=SIDEBAR_BG)
        sidebar.pack(side="left", fill="y", padx=(0,8))
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Search", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12,4))
        self.search_var = tk.StringVar()
        self.search_entry = ctk.CTkEntry(sidebar, textvariable=self.search_var, placeholder_text="Name, username, email…")
        self.search_entry.pack(fill="x", padx=12)

        ctk.CTkLabel(sidebar, text="Status", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12,4))
        self.status_var = tk.StringVar(value="Any")
        self.status_cb = ctk.CTkComboBox(sidebar, values=["Any", "off", "active", "inactive"], variable=self.status_var, width=120)
        self.status_cb.pack(anchor="w", padx=12)

        btn_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(12,8))
        ctk.CTkButton(btn_row, text="Search", command=self._do_search).pack(side="left", padx=(0,6))
        ctk.CTkButton(btn_row, text="Clear",  command=self._clear_search).pack(side="left")

        # Content area (cards)
        content = ctk.CTkFrame(body, corner_radius=12, fg_color=CARD_BG)
        content.pack(side="left", fill="both", expand=True)

        # Scrollable canvas for cards
        container = ctk.CTkFrame(content, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=8)

        self.canvas = tk.Canvas(container, highlightthickness=0, bg=APP_BG[0] if ctk.get_appearance_mode()=="Light" else APP_BG[1])
        vscroll = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.cards_frame = ctk.CTkFrame(self.canvas, fg_color="transparent")
        self.cards_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=vscroll.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        # Footer
        foot = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        foot.pack(side="bottom", fill="x")
        ctk.CTkLabel(foot, text="Mars Capital", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(foot, text="Work hard in silence; let success make the noise.", text_color=MUTED_TX)\
            .pack(side="right", padx=12, pady=6)

        self.user_cards = {}  # user_id -> widgets
        # live search typing
        self._search_job = None

        def on_change(*_):
            if self._search_job:
                self.after_cancel(self._search_job)
            self._search_job = self.after(300, self._do_search)
        self.search_var.trace_add("write", on_change)
        self.status_var.trace_add("write", on_change)

        # initial search
        self._do_search()

    # External setter
    def set_admin_name(self, name: str):
        self.admin_name.set(f"Signed in as: {name}")

    def _logout(self):
        self.master.logout()

    # search helpers
    def _do_search(self):
        text = self.search_var.get().strip() or None
        st = self.status_var.get().strip()
        status = None if st == "Any" else st
        try:
            users = list_users(search=text, status=status, hide_admin=True)
        except Exception as e:
            print("Search error:", e)
            users = []
        self.apply_user_delta(users)

    def _clear_search(self):
        self.search_var.set("")
        self.status_var.set("Any")
        self._do_search()

    def open_create_user(self):
        self.master.auto_refresh_enabled = False
        try:
            CreateUserDialog(self).wait_window()
        finally:
            self.master.auto_refresh_enabled = True
        self._do_search()

    # incremental apply + totals
    def apply_user_delta(self, users):
        existing_ids = set(self.user_cards.keys())
        new_ids = set(u["id"] for u in users)

        # remove missing cards
        for uid in existing_ids - new_ids:
            info = self.user_cards.pop(uid, None)
            if info:
                info["frame"].destroy()

        # place/update cards
        cols = 3
        users_sorted = sorted(users, key=lambda x: (x.get("name") or "", x.get("username") or ""))

        for idx, u in enumerate(users_sorted):
            uid = u["id"]
            info = self.user_cards.get(uid)
            if info is None:
                card = ctk.CTkFrame(self.cards_frame, corner_radius=12, fg_color=CARD_BG)
                top = ctk.CTkFrame(card, fg_color="transparent")
                top.pack(fill="x", padx=12, pady=10)
                name_lbl = ctk.CTkLabel(top, text=u["name"] or "", font=ctk.CTkFont(size=14, weight="bold"))
                name_lbl.pack(anchor="w")
                user_lbl = ctk.CTkLabel(top, text=f"@{u['username']}", text_color=MUTED_TX)
                user_lbl.pack(anchor="w")
                dept_lbl = ctk.CTkLabel(top, text=f"Dept: {u['department']}", text_color=MUTED_TX)
                dept_lbl.pack(anchor="w")
                status_lbl = ctk.CTkLabel(top, text=f"Status: {u['status'].lower()}")
                # color status inline
                color = {"active": "#22c55e", "inactive": "#ef4444", "off": "#000000"}.get(u["status"].lower(), None)
                if color:
                    status_lbl.configure(text_color=color)
                status_lbl.pack(anchor="w", pady=(4,0))

                # single action: View Details
                btn_row = ctk.CTkFrame(card, fg_color="transparent")
                btn_row.pack(fill="x", padx=12, pady=(6, 12))
                ctk.CTkButton(btn_row, text="View Details",
                              command=lambda uid=uid, uname=u["name"] or u["username"]: self.open_details(uid, uname))\
                    .pack(side="left")

                info = {"frame": card, "name_lbl": name_lbl, "user_lbl": user_lbl, "dept_lbl": dept_lbl, "status_lbl": status_lbl}
                self.user_cards[uid] = info
            else:
                # tiny diffs
                name_txt = u["name"] or ""
                if info["name_lbl"].cget("text") != name_txt:
                    info["name_lbl"].configure(text=name_txt)
                user_txt = f"@{u['username']}"
                if info["user_lbl"].cget("text") != user_txt:
                    info["user_lbl"].configure(text=user_txt)
                dept_txt = f"Dept: {u['department']}"
                if info["dept_lbl"].cget("text") != dept_txt:
                    info["dept_lbl"].configure(text=dept_txt)
                status_txt = f"Status: {u['status'].lower()}"
                if info["status_lbl"].cget("text") != status_txt:
                    info["status_lbl"].configure(text=status_txt)
                color = {"active": "#22c55e", "inactive": "#ef4444", "off": "#000000"}.get(u["status"].lower(), None)
                if color:
                    info["status_lbl"].configure(text_color=color)

            r, c = divmod(idx, cols)
            self.user_cards[uid]["frame"].grid(row=r, column=c, padx=8, pady=8, sticky="nsew")

        # column weights
        for i in range(cols):
            self.cards_frame.grid_columnconfigure(i, weight=1,minsize=490)

        # ---- totals strip update ----
        active_count = sum(1 for u in users if (u.get("status") or "").lower() == "active")
        inactive_count = sum(1 for u in users if (u.get("status") or "").lower() == "inactive")

        # Overtime today total across visible users
        today = datetime.now().date()
        start = str(today)
        end = str(today)
        overtime_total = 0
        try:
            for u in users:
                try:
                    overtime_total += int(fetch_overtime_sum(u["id"], start, end) or 0)
                except Exception:
                    pass
        except Exception:
            pass

        self.total_active_sv.set(str(active_count))
        self.total_inactive_sv.set(str(inactive_count))
        self.total_overtime_sv.set(seconds_to_hhmmss(overtime_total))

    # Details hub (History/Media/Update/Delete)
    def open_details(self, user_id, user_name):
        self.master.auto_refresh_enabled = False
        try:
            DetailDialog(self, user_id, user_name).wait_window()
        finally:
            self.master.auto_refresh_enabled = True
        self._do_search()


# =============================
# Dialogs (CustomTk versions)
# =============================
class CreateUserDialog(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Create User")
        self.grab_set()
        self.resizable(False, False)
        self.configure(fg_color=BAR_BG)

        p = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        p.pack(fill="both", expand=True, padx=12, pady=12)

        self.v_username = tk.StringVar()
        self.v_name = tk.StringVar()
        self.v_dept = tk.StringVar()
        self.v_email = tk.StringVar()
        self.v_password = tk.StringVar()
        self.v_shift_start = tk.StringVar(value="09:00:00")
        self.v_shift_end = tk.StringVar(value="18:00:00")

        def row(label, var, is_pwd=False):
            ctk.CTkLabel(p, text=label).pack(anchor="w", pady=(6, 0))
            ctk.CTkEntry(p, textvariable=var, show="•" if is_pwd else None, placeholder_text=label).pack(fill="x")

        row("Username", self.v_username)
        row("Name", self.v_name)
        row("Department", self.v_dept)
        row("Email", self.v_email)
        row("Password", self.v_password, is_pwd=True)
        row("Shift Start (HH:MM:SS)", self.v_shift_start)
        row("Shift End (HH:MM:SS)", self.v_shift_end)

        ctk.CTkButton(p, text="Create", command=self.do_create).pack(pady=10)

    def do_create(self):
        try:
            admin_create_user(
                self.v_username.get().strip(),
                self.v_name.get().strip(),
                self.v_dept.get().strip(),
                self.v_email.get().strip(),
                self.v_password.get().strip(),
                shift_start_time=self.v_shift_start.get().strip() or "09:00:00",
                shift_end_time=self.v_shift_end.get().strip() or "18:00:00",
            )
            messagebox.showinfo("Done", "User created")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))


class UpdateUserDialog(ctk.CTkToplevel):
    def __init__(self, master, urow):
        super().__init__(master)
        self.title("Update User")
        self.grab_set()
        self.resizable(False, False)
        self.configure(fg_color=BAR_BG)

        p = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        p.pack(fill="both", expand=True, padx=12, pady=12)

        self.user_id = urow["id"]
        self.v_name = tk.StringVar(value=urow.get("name") or "")
        self.v_dept = tk.StringVar(value=urow.get("department") or "")
        self.v_email = tk.StringVar(value=urow.get("email") or "")
        self.v_username = tk.StringVar(value=urow.get("username") or "")
        self.v_shift_start = tk.StringVar(value=str(urow.get("shift_start_time") or "09:00:00"))
        self.v_shift_end = tk.StringVar(value=str(urow.get("shift_end_time") or "18:00:00"))
        self.v_pass1 = tk.StringVar(value="")
        self.v_pass2 = tk.StringVar(value="")

        def row(label, var, is_pwd=False):
            ctk.CTkLabel(p, text=label).pack(anchor="w", pady=(6, 0))
            ctk.CTkEntry(p, textvariable=var, show="•" if is_pwd else None, placeholder_text=label).pack(fill="x")

        row("Name", self.v_name)
        row("Department", self.v_dept)
        row("Email", self.v_email)
        row("Username", self.v_username)
        row("Shift Start (HH:MM:SS)", self.v_shift_start)
        row("Shift End (HH:MM:SS)", self.v_shift_end)
        ctk.CTkLabel(p, text="New Password (leave blank to keep)").pack(anchor="w", pady=(10, 0))
        ctk.CTkEntry(p, textvariable=self.v_pass1, show="•", placeholder_text="New Password").pack(fill="x")
        ctk.CTkLabel(p, text="Confirm Password").pack(anchor="w", pady=(6, 0))
        ctk.CTkEntry(p, textvariable=self.v_pass2, show="•", placeholder_text="Confirm Password").pack(fill="x")

        ctk.CTkButton(p, text="Save", command=self.do_save).pack(pady=12)

    def do_save(self):
        try:
            name = self.v_name.get().strip()
            dept = self.v_dept.get().strip()
            email = self.v_email.get().strip()
            username = self.v_username.get().strip()
            shift_start = self.v_shift_start.get().strip()
            shift_end = self.v_shift_end.get().strip()
            p1 = (self.v_pass1.get() or "").strip()
            p2 = (self.v_pass2.get() or "").strip()

            if not username:
                messagebox.showerror("Validation", "Username cannot be empty.")
                return
            if p1 or p2:
                if p1 != p2:
                    messagebox.showerror("Validation", "Passwords do not match.")
                    return
                if len(p1) < 6:
                    messagebox.showerror("Validation", "Password must be at least 6 characters.")
                    return

            payload = dict(
                name=name,
                department=dept,
                email=email,
                username=username,
                shift_start_time=shift_start,
                shift_end_time=shift_end,
            )
            if p1:
                payload["password_hash"] = hash_password(p1)

            admin_update_user(self.user_id, **payload)
            messagebox.showinfo("Success", "User updated successfully.")
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", str(e))


class DetailDialog(ctk.CTkToplevel):
    """
    Central detail hub: tabs for Overview, History, Media, Update and a Delete button
    History includes a sidebar with filters; events with type 'inactive' are highlighted red.
    Media hides id/event_id/duration/mime columns per your request.
    """
    def __init__(self, master, user_id, user_name):
        super().__init__(master)
        self.title(f"User Details — {user_name}")
        self.geometry("1040x640")
        self.grab_set()
        self.user_id = user_id
        self.configure(fg_color=APP_BG)

        # Tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)

        # ========== Overview ==========
        tab_over = ctk.CTkFrame(nb, fg_color=CARD_BG)
        nb.add(tab_over, text="Overview")

        # Pull fresh user
        try:
            fresh = get_user_by_id(self.user_id) or {}
        except Exception:
            fresh = {}

        over_card = ctk.CTkFrame(tab_over, corner_radius=12, fg_color=CARD_BG)
        over_card.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(over_card, text=f"Name: {fresh.get('name') or ''}").pack(anchor="w", padx=12, pady=(10,0))
        ctk.CTkLabel(over_card, text=f"Username: @{fresh.get('username') or ''}", text_color=MUTED_TX)\
            .pack(anchor="w", padx=12)
        ctk.CTkLabel(over_card, text=f"Department: {fresh.get('department') or ''}", text_color=MUTED_TX)\
            .pack(anchor="w", padx=12, pady=(0,10))
        st = (fresh.get("status") or "").lower()
        status_color = {"active":"#22c55e","inactive":"#ef4444","off":"#000000"}.get(st, None)
        ctk.CTkLabel(over_card, text=f"Status: {st}", text_color=status_color).pack(anchor="w", padx=12, pady=(0,10))

        # Actions row (the 4 buttons live here)
        actions = ctk.CTkFrame(tab_over, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(0,10))
        ctk.CTkButton(actions, text="History", width=120, command=lambda: nb.select(tab_over_history)).pack(side="left", padx=(0,8))
        ctk.CTkButton(actions, text="Media", width=120, command=lambda: nb.select(tab_media)).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Update", width=120,
                      command=lambda: self._open_update_then_refresh(nb, tab_over)).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Delete", fg_color="#ef4444",
                      command=self._delete_user_confirm).pack(side="left", padx=8)

        # ========== History (with sidebar) ==========
        tab_over_history = ctk.CTkFrame(nb, fg_color=APP_BG)
        nb.add(tab_over_history, text="History")

        hist_body = ctk.CTkFrame(tab_over_history, fg_color="transparent")
        hist_body.pack(fill="both", expand=True, padx=8, pady=8)

        # Sidebar filters
        side = ctk.CTkFrame(hist_body, width=260, corner_radius=12, fg_color=SIDEBAR_BG)
        side.pack(side="left", fill="y", padx=(0,8))
        side.pack_propagate(False)

        ctk.CTkLabel(side, text="Filters", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12,6))
        self.v_period = tk.StringVar(value="Custom")
        ctk.CTkLabel(side, text="Period").pack(anchor="w", padx=12)
        ctk.CTkComboBox(side, values=["Day","Week","Month","Custom"], variable=self.v_period, width=120).pack(anchor="w", padx=12, pady=(0,6))

        self.v_start = tk.StringVar()
        self.v_end   = tk.StringVar()

        ctk.CTkLabel(side, text="Start (YYYY-MM-DD)").pack(anchor="w", padx=12)
        ctk.CTkEntry(side, textvariable=self.v_start, placeholder_text="YYYY-MM-DD").pack(fill="x", padx=12, pady=(0,6))
        ctk.CTkLabel(side, text="End (YYYY-MM-DD)").pack(anchor="w", padx=12)
        ctk.CTkEntry(side, textvariable=self.v_end, placeholder_text="YYYY-MM-DD").pack(fill="x", padx=12, pady=(0,6))

        btns = ctk.CTkFrame(side, fg_color="transparent")
        btns.pack(anchor="w", padx=12, pady=(8,12))
        ctk.CTkButton(btns, text="Search", command=self._hist_reload).pack(side="left", padx=(0,6))
        ctk.CTkButton(btns, text="Clear",  command=self._hist_clear).pack(side="left")

        # Totals strip
        totals = ctk.CTkFrame(hist_body, fg_color="transparent")
        totals.pack(side="top", fill="x", padx=8, pady=(0,6))

        def make_total(parent, label, color):
            card = ctk.CTkFrame(parent, corner_radius=12, fg_color=CARD_BG)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            ctk.CTkLabel(inner, text=label, text_color=MUTED_TX).pack(anchor="w")
            value_sv = tk.StringVar(value="00:00:00")
            lbl = ctk.CTkLabel(inner, textvariable=value_sv, font=ctk.CTkFont(size=16, weight="bold"))
            lbl.configure(text_color=color)
            lbl.pack(anchor="w")
            return card, value_sv

        totals_row = ctk.CTkFrame(totals, fg_color="transparent")
        totals_row.pack(fill="x")
        card_a, self.t_active_sv = make_total(totals_row, "Total Active", "#10b981")
        card_i, self.t_inactive_sv = make_total(totals_row, "Total Inactive (est.)", "#ef4444")
        card_o, self.t_overtime_sv = make_total(totals_row, "Total Overtime", "#3b82f6")
        card_a.pack(side="left", fill="x", expand=True, padx=(0,6))
        card_i.pack(side="left", fill="x", expand=True, padx=6)
        card_o.pack(side="left", fill="x", expand=True, padx=(6,0))

        # Table area
        table_wrap = ctk.CTkFrame(hist_body, corner_radius=12, fg_color=CARD_BG)
        table_wrap.pack(fill="both", expand=True, padx=8, pady=4)

        cols = ("username", "email", "event", "occurred_at", "active_duration")
        self.tree_hist = ttk.Treeview(table_wrap, columns=cols, show="headings")
        headers = {
            "username": "username", "email": "email", "event": "event",
            "occurred_at": "occurred_at", "active_duration": "active_duration"
        }
        for c in cols:
            self.tree_hist.heading(c, text=headers[c])
            self.tree_hist.column(c, width=170 if c not in ("email", "occurred_at") else 240, anchor="w")
        self.tree_hist.pack(fill="both", expand=True, padx=6, pady=6)

        # tag style for inactive events
        self.tree_hist.tag_configure("inactive_row", background=INACTIVE_ROW_BG)

        # initial load
        self._hist_reload()

        # ========== Media ==========
        tab_media = ctk.CTkFrame(nb, fg_color=APP_BG)
        nb.add(tab_media, text="Media")

        # Screenshots (simple columns: taken_at, url)
        scr_card = ctk.CTkFrame(tab_media, corner_radius=12, fg_color=CARD_BG)
        scr_card.pack(fill="both", expand=True, padx=8, pady=(8,4))
        ctk.CTkLabel(scr_card, text="Screenshots", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10,0))

        self.tree_scr = ttk.Treeview(scr_card, columns=("taken_at","url"), show="headings", height=8)
        self.tree_scr.heading("taken_at", text="taken_at")
        self.tree_scr.heading("url", text="url")
        self.tree_scr.column("taken_at", width=220, anchor="w")
        self.tree_scr.column("url", width=600, anchor="w")
        self.tree_scr.pack(fill="both", expand=True, padx=10, pady=(6,6))
        ctk.CTkButton(scr_card, text="Open selected", command=self.open_selected_screenshot).pack(anchor="e", padx=10, pady=(0,10))

        # Recordings (simple columns: recorded_at, url)
        rec_card = ctk.CTkFrame(tab_media, corner_radius=12, fg_color=CARD_BG)
        rec_card.pack(fill="both", expand=True, padx=8, pady=(4,8))
        ctk.CTkLabel(rec_card, text="Recordings", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10,0))

        self.tree_rec = ttk.Treeview(rec_card, columns=("recorded_at","url"), show="headings", height=8)
        self.tree_rec.heading("recorded_at", text="recorded_at")
        self.tree_rec.heading("url", text="url")
        self.tree_rec.column("recorded_at", width=220, anchor="w")
        self.tree_rec.column("url", width=600, anchor="w")
        self.tree_rec.pack(fill="both", expand=True, padx=10, pady=(6,6))
        ctk.CTkButton(rec_card, text="Open selected", command=self.open_selected_recording).pack(anchor="e", padx=10, pady=(0,10))

        # load media
        self._reload_media()

        # ========== Update ==========
        tab_update = ctk.CTkFrame(nb, fg_color=APP_BG)
        nb.add(tab_update, text="Update")

        fresh = get_user_by_id(self.user_id) or {}
        ctk.CTkLabel(tab_update, text="Update User", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=12, pady=(12,0))
        ctk.CTkButton(tab_update, text="Open Update Form", command=lambda: self._open_update_then_refresh(nb, tab_update))\
            .pack(anchor="w", padx=12, pady=(8,12))

    def _delete_user_confirm(self):
        if not messagebox.askyesno("Confirm", "Delete this user? This cannot be undone."):
            return
        try:
            admin_delete_user(self.user_id)
            messagebox.showinfo("Deleted", "User removed.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _compute_dates(self):
        today = datetime.now().date()
        p = self.v_period.get()
        if p == "Day":
            start = end = today
        elif p == "Week":
            start = today - timedelta(days=today.weekday())
            end = start + timedelta(days=6)
        elif p == "Month":
            start = today.replace(day=1)
            if start.month == 12:
                end = start.replace(year=start.year+1, month=1, day=1) - timedelta(days=1)
            else:
                end = start.replace(month=start.month+1, day=1) - timedelta(days=1)
        else:
            s = self.v_start.get().strip() or None
            e = self.v_end.get().strip() or None
            return (s, e)
        return (str(start), str(end))

    def _hist_clear(self):
        self.v_period.set("Custom")
        self.v_start.set("")
        self.v_end.set("")
        self._hist_reload()

    def _hist_reload(self):
        for i in self.tree_hist.get_children():
            self.tree_hist.delete(i)

        start, end = self._compute_dates()
        rows = fetch_user_inactive_history(self.user_id, start, end, limit=1500)

        total_active = 0
        INACTIVITY_THRESHOLD = 10
        inactive_est = 0

        for r in rows:
            ad = int(r.get("active_duration_seconds") or 0)
            total_active += ad
            vals = (r["username"], r["email"], r["event_type"], str(r["occurred_at"]), seconds_to_hhmmss(ad))
            tag = "inactive_row" if (r.get("event_type") or "").lower() == "inactive" else ""
            self.tree_hist.insert("", "end", values=vals, tags=(tag,))

            if (r.get("event_type") or "").lower() == "inactive":
                inactive_est += INACTIVITY_THRESHOLD

        self.t_active_sv.set(seconds_to_hhmmss(total_active))
        self.t_inactive_sv.set(seconds_to_hhmmss(inactive_est))

        # Overtime sum for this user in range
        ot_sum = fetch_overtime_sum(self.user_id, start, end)
        self.t_overtime_sv.set(seconds_to_hhmmss(ot_sum))

    def _reload_media(self):
        for i in getattr(self, "tree_scr").get_children():
            self.tree_scr.delete(i)
        for i in getattr(self, "tree_rec").get_children():
            self.tree_rec.delete(i)

        scrs = fetch_screenshots_for_user(self.user_id, limit=200)
        for s in scrs:
            self.tree_scr.insert("", "end", values=(str(s["taken_at"]), s["url"]))

        recs = fetch_recordings_for_user(self.user_id, limit=100)
        for r in recs:
            self.tree_rec.insert("", "end", values=(str(r["recorded_at"]), r["url"]))

    def open_selected_screenshot(self):
        sel = self.tree_scr.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a screenshot row.")
            return
        url = self.tree_scr.item(sel[0])["values"][1]
        webbrowser.open(url)

    def open_selected_recording(self):
        sel = self.tree_rec.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a recording row.")
            return
        url = self.tree_rec.item(sel[0])["values"][1]
        webbrowser.open(url)

    def _open_update_then_refresh(self, nb, current_tab):
        try:
            fresh = get_user_by_id(self.user_id)
            if not fresh:
                messagebox.showerror("Error", "User not found.")
                return
            UpdateUserDialog(self, fresh).wait_window()
        finally:
            # refresh overview text & history/media caches
            nb.select(current_tab)  # stay on same tab
            self._hist_reload()
            self._reload_media()


# -----------------------------
# Launcher
# -----------------------------
if __name__ == "__main__":
    try:
        print("Starting AdminApp…")
        app = AdminApp()
        app.mainloop()
    except Exception:
        tb = traceback.format_exc()
        print(tb)
        try:
            messagebox.showerror("Admin crashed", tb)
        except Exception:
            pass
        sys.exit(1)
