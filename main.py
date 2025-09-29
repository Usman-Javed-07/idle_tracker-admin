import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from plyer import notification

from backend.models import (
    init_tables, list_users, fetch_unnotified_inactive_events, mark_event_notified,
    fetch_user_inactive_history
)
from backend.auth import login, admin_create_user
from backend.config import ADMIN_BOOTSTRAP

REFRESH_MS = 2000  # poll db every 2s

class AdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Dashboard - Idle Tracker")
        self.geometry("1000x650")
        self.resizable(True, True)
        init_tables()

        self.frames = {}
        for F in (AdminLoginFrame, AdminDashboardFrame):
            frame = F(self)
            self.frames[F.__name__] = frame

        self.show_frame("AdminLoginFrame")

    def show_frame(self, name):
        for f in self.frames.values(): f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def on_admin_logged_in(self, admin_user):
        if admin_user["role"] != "admin":
            messagebox.showwarning("Access denied", "Admin only.")
            return
        self.show_frame("AdminDashboardFrame")
        self.after(REFRESH_MS, self._poll_new_inactive)

    def _poll_new_inactive(self):
        # desktop toast for new inactive events; mark as notified
        try:
            rows = fetch_unnotified_inactive_events()
            for r in rows:
                msg = (f"{r['name']} ({r['username']}, {r['email']}, {r['department']}) "
                       f"is INACTIVE at {r['occurred_at']} "
                       f"(active streak: {seconds_to_hhmmss(r['active_duration_seconds'])}).")
                try:
                    notification.notify(title="User Inactive", message=msg, timeout=4)
                except Exception:
                    pass
                mark_event_notified(r["id"])
        except Exception as e:
            print("Poll error:", e)

        # also refresh the grid
        self.frames["AdminDashboardFrame"].load_users()
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

        # top bar
        top = ttk.Frame(self); top.pack(fill="x")
        ttk.Label(top, text="Users", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(top, text="Create User", command=self.open_create_user).pack(side="right")

        # scrollable card area
        container = ttk.Frame(self); container.pack(fill="both", expand=True, pady=(10,0))
        canvas = tk.Canvas(container, highlightthickness=0)
        vscroll = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.cards_frame = ttk.Frame(canvas)

        self.cards_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=vscroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        self.card_widgets = []
        self.load_users()

    def open_create_user(self):
        CreateUserDialog(self).wait_window()
        self.load_users()

    def load_users(self):
        # clear old
        for w in self.card_widgets: w.destroy()
        self.card_widgets.clear()

        users = list_users()
        cols = 4
        r = c = 0
        for u in users:
            card = ttk.Frame(self.cards_frame, padding=12, relief="ridge")
            ttk.Label(card, text=u["name"], font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ttk.Label(card, text=f"@{u['username']}").pack(anchor="w")
            ttk.Label(card, text=f"Dept: {u['department']}").pack(anchor="w")
            ttk.Label(card, text=f"Status: {u['status']}").pack(anchor="w", pady=(4,0))
            ttk.Button(card, text="History", command=lambda uid=u["id"], uname=u["name"]: self.open_history(uid, uname)).pack(anchor="e", pady=(6,0))

            card.grid(row=r, column=c, padx=8, pady=8, sticky="nsew")
            self.card_widgets.append(card)

            c += 1
            if c == cols:
                c = 0; r += 1

        # make grid stretch nicely
        for i in range(cols):
            self.cards_frame.grid_columnconfigure(i, weight=1)

    def open_history(self, user_id, user_name):
        HistoryDialog(self, user_id, user_name)


class CreateUserDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Create User")
        self.grab_set()
        self.resizable(False, False)
        p = ttk.Frame(self, padding=12); p.pack(fill="both", expand=True)

        self.v_username = tk.StringVar()
        self.v_name = tk.StringVar()
        self.v_dept = tk.StringVar()
        self.v_email = tk.StringVar()
        self.v_password = tk.StringVar()
        self.v_shift = tk.StringVar(value="09:00:00")

        for label, var in [
            ("Username", self.v_username),
            ("Name", self.v_name),
            ("Department", self.v_dept),
            ("Email", self.v_email),
            ("Password", self.v_password),
            ("Shift Start (HH:MM:SS)", self.v_shift),
        ]:
            ttk.Label(p, text=label).pack(anchor="w", pady=(6,0))
            show = "*" if label=="Password" else None
            ttk.Entry(p, textvariable=var, show=show).pack(fill="x")

        ttk.Button(p, text="Create", command=self.do_create).pack(pady=10)

    def do_create(self):
        try:
            admin_create_user(
                self.v_username.get().strip(),
                self.v_name.get().strip(),
                self.v_dept.get().strip(),
                self.v_email.get().strip(),
                self.v_password.get().strip(),
                shift_start_time=self.v_shift.get().strip() or "09:00:00",
            )
            messagebox.showinfo("Done", "User created")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))


class HistoryDialog(tk.Toplevel):
    def __init__(self, master, user_id, user_name):
        super().__init__(master)
        self.title(f"Inactive History — {user_name}")
        self.resizable(True, True)
        self.geometry("800x400")
        self.grab_set()

        cols = ("id","username","email","event","occurred_at","notified","active_duration")
        tree = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=120 if c!="email" else 200, anchor="w")
        tree.pack(fill="both", expand=True)

        rows = fetch_user_inactive_history(user_id, limit=300)
        for r in rows:
            tree.insert("", "end", values=(
                r["id"], r["username"], r["email"], r["event_type"], str(r["occurred_at"]),
                r["notified"], seconds_to_hhmmss(r["active_duration_seconds"] or 0)
            ))


def seconds_to_hhmmss(sec):
    if sec is None: return "00:00:00"
    h = sec // 3600; m = (sec % 3600) // 60; s = sec % 60
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"


if __name__ == "__main__":
    import logging, os, sys, traceback
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(
        filename=os.path.join("logs", "admin_app.log"),
        level=logging.DEBUG, format="%(asctime)s | %(levelname)s | %(message)s"
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
