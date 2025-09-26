import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from plyer import notification

from backend.models import init_tables, fetch_recent_events, fetch_unnotified_inactive_events, mark_event_notified, get_user_by_username_or_email
from backend.auth import login
from backend.config import ADMIN_BOOTSTRAP

REFRESH_MS = 2000  # poll DB every 2s for new inactive events

class AdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Dashboard - Idle Tracker")
        self.geometry("700x420")
        self.resizable(True, True)
        init_tables()

        self.frames = {}
        for F in (AdminLoginFrame, AdminDashboardFrame):
            frame = F(self)
            self.frames[F.__name__] = frame

        self.show_frame("AdminLoginFrame")

    def show_frame(self, name):
        for f in self.frames.values():
            f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def on_admin_logged_in(self, admin_user):
        if admin_user["role"] != "admin":
            messagebox.showwarning("Access denied", "This app is for the admin only.")
            return
        self.show_frame("AdminDashboardFrame")
        self.after(REFRESH_MS, self._poll_new_inactive)

    def _poll_new_inactive(self):
        # Check for unnotified 'inactive' events, notify, then mark notified.
        try:
            rows = fetch_unnotified_inactive_events()
            for r in rows:
                title = "User Inactive"
                msg = f"{r['username']} ({r['email']}) is inactive at {r['occurred_at']}."
                try:
                    notification.notify(title=title, message=msg, timeout=4)
                except Exception:
                    pass
                mark_event_notified(r["id"])
        except Exception as e:
            # Avoid crashing if DB hiccups
            print("Poll error:", e)

        # Also refresh the table on screen
        self.frames["AdminDashboardFrame"].load_recent()
        self.after(REFRESH_MS, self._poll_new_inactive)


class AdminLoginFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=16)
        ttk.Label(self, text="Admin Login", font=("Segoe UI", 16, "bold")).pack(pady=(0,12))

        self.login_id = tk.StringVar(value=ADMIN_BOOTSTRAP["email"])
        self.login_pwd = tk.StringVar(value=ADMIN_BOOTSTRAP["password"])

        ttk.Label(self, text="Username or Email").pack(anchor="w")
        ttk.Entry(self, textvariable=self.login_id).pack(fill="x")

        ttk.Label(self, text="Password").pack(anchor="w", pady=(8,0))
        ttk.Entry(self, show="*", textvariable=self.login_pwd).pack(fill="x")

        ttk.Button(self, text="Login", command=self.do_login).pack(pady=10)

    def do_login(self):
        try:
            admin = login(self.login_id.get().strip(), self.login_pwd.get().strip())
            if not admin:
                messagebox.showerror("Login failed", "Invalid credentials")
                return
            self.master.on_admin_logged_in(admin)
        except Exception as e:
            messagebox.showerror("Error", str(e))


class AdminDashboardFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        ttk.Label(self, text="Recent Activity", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0,8))

        cols = ("id","username","email","event_type","occurred_at","notified")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=110 if c!="email" else 180, anchor="w")
        self.tree.pack(fill="both", expand=True)

        btnbar = ttk.Frame(self)
        btnbar.pack(fill="x", pady=8)
        ttk.Button(btnbar, text="Refresh now", command=self.load_recent).pack(side="left")
        ttk.Label(btnbar, text="(Auto-refresh every 2s)").pack(side="left", padx=8)

        self.load_recent()

    def load_recent(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        rows = fetch_recent_events(limit=100)
        for r in rows:
            self.tree.insert("", "end", values=(
                r["id"], r["username"], r["email"], r["event_type"], str(r["occurred_at"]), r["notified"]
            ))


if __name__ == "__main__":
    app = AdminApp()
    app.mainloop()

if __name__ == "__main__":
    import logging, os, sys, traceback
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename=os.path.join("logs", "admin_app.log"),
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )
    try:
        print("Starting AdminApp…")
        app = AdminApp()
        app.after(50, lambda: (app.lift(), app.attributes("-topmost", True)))
        app.after(1000, lambda: app.attributes("-topmost", False))
        app.mainloop()
    except Exception:
        tb = traceback.format_exc()
        logging.error(tb)
        print("Admin app crashed. See logs\\admin_app.log")
        print(tb)
        sys.exit(1)
