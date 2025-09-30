import os
import sys
import traceback
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from plyer import notification

from backend.models import (
    init_tables, list_users, fetch_unnotified_inactive_events, mark_event_notified,
    fetch_user_inactive_history, fetch_screenshots_for_user, fetch_recordings_for_user,
    list_admin_emails,
    admin_update_user, admin_delete_user, fetch_overtime_sum
)
from backend.auth import login, admin_create_user
from backend.config import ADMIN_BOOTSTRAP
from backend.notify import send_email

try:
    from backend.config import ALERT_RECIPIENTS
except Exception:
    ALERT_RECIPIENTS = []

REFRESH_MS = 2000  # poll db every 2s

def seconds_to_hhmmss(sec):
    if sec is None: return "00:00:00"
    h = sec // 3600; m = (sec % 3600) // 60; s = sec % 60
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"


class AdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Admin Dashboard - Idle Tracker")
        self.geometry("1180x760")
        self.resizable(True, True)
        init_tables()

        self.frames = {}
        for F in (AdminLoginFrame, AdminDashboardFrame):
            frame = F(self); self.frames[F.__name__] = frame
        self.show_frame("AdminLoginFrame")

        self._poll_job = None
        self.auto_refresh_enabled = False  # enable after login

        # center on screen
        self.after(10, self._center_on_screen)

    def _center_on_screen(self):
        self.update_idletasks()
        w = self.winfo_width(); h = self.winfo_height()
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        x = (sw // 2) - (w // 2); y = (sh // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def show_frame(self, name):
        for f in self.frames.values(): f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def on_admin_logged_in(self, admin_user):
        if admin_user["role"] != "admin":
            messagebox.showwarning("Access denied", "Admin only.")
            return
        self.show_frame("AdminDashboardFrame")
        self.auto_refresh_enabled = True
        self._schedule_poll()

    def _schedule_poll(self):
        if self._poll_job:
            try: self.after_cancel(self._poll_job)
            except Exception: pass
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
                    notification.notify(title="User Inactive", message=msg, timeout=4, app_name="Mars Capital")
                except Exception:
                    pass

                try:
                    recipients = {r.get("email")}
                    recipients.update(e for e in list_admin_emails() if e)
                    if ADMIN_BOOTSTRAP.get("email"): recipients.add(ADMIN_BOOTSTRAP["email"])
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


class AdminLoginFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=16)
        ttk.Label(self, text="Admin Login", font=("Segoe UI", 16, "bold")).pack(pady=(0,12))
        self.login_id = tk.StringVar(value=ADMIN_BOOTSTRAP.get("email",""))
        self.login_pwd = tk.StringVar(value=ADMIN_BOOTSTRAP.get("password",""))
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

        self.search_var = tk.StringVar()
        sbox = ttk.Entry(top, textvariable=self.search_var, width=40)
        sbox.pack(side="left", padx=10)

        self.status_var = tk.StringVar(value="Any")
        ttk.Label(top, text="Status:").pack(side="left", padx=(10,4))
        cb = ttk.Combobox(top, textvariable=self.status_var, width=12,
                          values=["Any","off","active","inactive"], state="readonly")
        cb.pack(side="left")

        self._search_job = None
        def on_change(*_):
            if self._search_job: self.after_cancel(self._search_job)
            self._search_job = self.after(300, self._do_search)
        self.search_var.trace_add("write", on_change)
        self.status_var.trace_add("write", on_change)

        ttk.Button(top, text="Search now", command=self._do_search).pack(side="left", padx=(8,0))
        ttk.Button(top, text="Clear", command=self._clear_search).pack(side="left", padx=(4,0))

        # Logout button
        ttk.Button(top, text="Logout", command=self._logout).pack(side="right")

        ttk.Button(top, text="Create User", command=self.open_create_user).pack(side="right", padx=(0,8))

        # scrollable card area
        container = ttk.Frame(self); container.pack(fill="both", expand=True, pady=(10,0))
        self.canvas = tk.Canvas(container, highlightthickness=0)
        vscroll = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.cards_frame = ttk.Frame(self.canvas)
        self.cards_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=vscroll.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        self.user_cards = {}  # user_id -> widgets
        self._do_search()

    def _logout(self):
        self.master.auto_refresh_enabled = False
        self.master.show_frame("AdminLoginFrame")

    # search helpers
    def _do_search(self):
        text = self.search_var.get().strip() or None
        st = self.status_var.get().strip()
        status = None if st == "Any" else st
        try:
            users = list_users(search=text, status=status, hide_admin=True)
        except Exception as e:
            print("Search error:", e); users = []
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

    # incremental apply
    def apply_user_delta(self, users):
        existing_ids = set(self.user_cards.keys())
        new_ids = set(u["id"] for u in users)

        # remove missing
        for uid in existing_ids - new_ids:
            info = self.user_cards.pop(uid, None)
            if info: info["frame"].destroy()

        cols = 4
        users_sorted = sorted(users, key=lambda x: (x.get("name") or "", x.get("username") or ""))

        for idx, u in enumerate(users_sorted):
            uid = u["id"]
            info = self.user_cards.get(uid)
            if info is None:
                frame = ttk.Frame(self.cards_frame, padding=12, relief="ridge")
                lbl_name = ttk.Label(frame, text=u["name"], font=("Segoe UI", 12, "bold")); lbl_name.pack(anchor="w")
                lbl_user = ttk.Label(frame, text=f"@{u['username']}"); lbl_user.pack(anchor="w")
                lbl_dept = ttk.Label(frame, text=f"Dept: {u['department']}"); lbl_dept.pack(anchor="w")
                lbl_status = ttk.Label(frame, text=f"Status: {u['status']}"); lbl_status.pack(anchor="w", pady=(4,0))

                # action row: History | Media | Update | Delete
                row2 = ttk.Frame(frame); row2.pack(fill="x", pady=(6,0))
                ttk.Button(row2, text="History",
                           command=lambda uid=uid, uname=u["name"]: self.open_history(uid, uname)).pack(side="left")
                ttk.Button(row2, text="Media",
                           command=lambda uid=uid, uname=u["name"]: self.open_media(uid, uname)).pack(side="left", padx=4)
                ttk.Button(row2, text="Update",
                           command=lambda u=u: self.open_update_user(u)).pack(side="left", padx=4)
                ttk.Button(row2, text="Delete",
                           command=lambda uid=uid: self.delete_user(uid)).pack(side="right")

                info = {"frame": frame, "lbl_name": lbl_name, "lbl_user": lbl_user,
                        "lbl_dept": lbl_dept, "lbl_status": lbl_status}
                self.user_cards[uid] = info
            else:
                # small diffs only
                if info["lbl_name"]["text"] != (u["name"] or ""): info["lbl_name"]["text"] = u["name"] or ""
                user_txt = f"@{u['username']}"
                if info["lbl_user"]["text"] != user_txt: info["lbl_user"]["text"] = user_txt
                dept_txt = f"Dept: {u['department']}"
                if info["lbl_dept"]["text"] != dept_txt: info["lbl_dept"]["text"] = dept_txt
                status_txt = f"Status: {u['status']}"
                if info["lbl_status"]["text"] != status_txt: info["lbl_status"]["text"] = status_txt

            r, c = divmod(idx, cols)
            self.user_cards[uid]["frame"].grid(row=r, column=c, padx=8, pady=8, sticky="nsew")

        for i in range(cols):
            self.cards_frame.grid_columnconfigure(i, weight=1)

    # dialogs
    def open_history(self, user_id, user_name):
        self.master.auto_refresh_enabled = False
        try:
            HistoryDialog(self, user_id, user_name).wait_window()
        finally:
            self.master.auto_refresh_enabled = True
        self._do_search()

    def open_media(self, user_id, user_name):
        self.master.auto_refresh_enabled = False
        try:
            MediaDialog(self, user_id, user_name).wait_window()
        finally:
            self.master.auto_refresh_enabled = True
        self._do_search()

    def open_update_user(self, urow):
        self.master.auto_refresh_enabled = False
        try:
            UpdateUserDialog(self, urow).wait_window()
        finally:
            self.master.auto_refresh_enabled = True
        self._do_search()

    def delete_user(self, user_id):
        if not messagebox.askyesno("Confirm", "Delete this user? This cannot be undone."):
            return
        try:
            admin_delete_user(user_id)
            self._do_search()
        except Exception as e:
            messagebox.showerror("Error", str(e))


class CreateUserDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Create User"); self.grab_set(); self.resizable(False, False)
        p = ttk.Frame(self, padding=12); p.pack(fill="both", expand=True)
        self.v_username = tk.StringVar(); self.v_name = tk.StringVar()
        self.v_dept = tk.StringVar(); self.v_email = tk.StringVar()
        self.v_password = tk.StringVar()
        self.v_shift_start = tk.StringVar(value="09:00:00")
        self.v_shift_end   = tk.StringVar(value="18:00:00")

        for label, var in [
            ("Username", self.v_username), ("Name", self.v_name), ("Department", self.v_dept),
            ("Email", self.v_email), ("Password", self.v_password),
            ("Shift Start (HH:MM:SS)", self.v_shift_start),
            ("Shift End (HH:MM:SS)", self.v_shift_end),
        ]:
            ttk.Label(p, text=label).pack(anchor="w", pady=(6,0))
            ttk.Entry(p, textvariable=var, show="*" if label=="Password" else None).pack(fill="x")

        ttk.Button(p, text="Create", command=self.do_create).pack(pady=10)

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


class UpdateUserDialog(tk.Toplevel):
    def __init__(self, master, urow):
        super().__init__(master)
        self.title("Update User"); self.grab_set(); self.resizable(False, False)
        p = ttk.Frame(self, padding=12); p.pack(fill="both", expand=True)

        self.user_id = urow["id"]
        self.v_name = tk.StringVar(value=urow.get("name") or "")
        self.v_dept = tk.StringVar(value=urow.get("department") or "")
        self.v_email = tk.StringVar(value=urow.get("email") or "")
        self.v_shift_start = tk.StringVar(value=str(urow.get("shift_start_time")))
        self.v_shift_end   = tk.StringVar(value=str(urow.get("shift_end_time") or "18:00:00"))

        for label, var in [
            ("Name", self.v_name), ("Department", self.v_dept), ("Email", self.v_email),
            ("Shift Start (HH:MM:SS)", self.v_shift_start), ("Shift End (HH:MM:SS)", self.v_shift_end),
        ]:
            ttk.Label(p, text=label).pack(anchor="w", pady=(6,0))
            ttk.Entry(p, textvariable=var).pack(fill="x")

        ttk.Button(p, text="Save", command=self.do_save).pack(pady=10)

    def do_save(self):
        try:
            admin_update_user(
                self.user_id,
                name=self.v_name.get().strip(),
                department=self.v_dept.get().strip(),
                email=self.v_email.get().strip(),
                shift_start_time=self.v_shift_start.get().strip(),
                shift_end_time=self.v_shift_end.get().strip(),
            )
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))


class HistoryDialog(tk.Toplevel):
    def __init__(self, master, user_id, user_name):
        super().__init__(master)
        self.title(f"Inactive History — {user_name}")
        self.resizable(True, True); self.geometry("980x540"); self.grab_set()

        self.user_id = user_id

        # Filter row: Period + Start/End
        filt = ttk.Frame(self); filt.pack(fill="x", padx=8, pady=8)
        self.v_period = tk.StringVar(value="Custom")
        ttk.Label(filt, text="Period").pack(side="left")
        ttk.Combobox(filt, textvariable=self.v_period, width=10,
                     values=["Day","Week","Month","Custom"], state="readonly").pack(side="left", padx=(4,12))

        self.v_start = tk.StringVar()
        self.v_end = tk.StringVar()
        ttk.Label(filt, text="Start (YYYY-MM-DD)").pack(side="left")
        ttk.Entry(filt, textvariable=self.v_start, width=12).pack(side="left", padx=(4,10))
        ttk.Label(filt, text="End (YYYY-MM-DD)").pack(side="left")
        ttk.Entry(filt, textvariable=self.v_end, width=12).pack(side="left", padx=(4,10))

        ttk.Button(filt, text="Search", command=self.reload).pack(side="left")
        ttk.Button(filt, text="Clear", command=self.clear).pack(side="left", padx=(4,0))

        # Totals strip (clean: no id/notified shown)
        totals = ttk.Frame(self); totals.pack(fill="x", padx=8, pady=(0,8))
        self.t_active = tk.StringVar(value="00:00:00")
        self.t_inactive = tk.StringVar(value="00:00:00")
        self.t_overtime = tk.StringVar(value="00:00:00")
        def tot(label, var):
            f = ttk.Frame(totals); f.pack(side="left", padx=16)
            ttk.Label(f, text=label).pack()
            ttk.Label(f, textvariable=var, font=("Consolas", 12, "bold")).pack()
        tot("Total Active", self.t_active)
        tot("Total Inactive (est.)", self.t_inactive)
        tot("Total Overtime", self.t_overtime)

        # Table
        cols = ("username","email","event","occurred_at","active_duration")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        headers = {
            "username":"username","email":"email","event":"event",
            "occurred_at":"occurred_at","active_duration":"active_duration"
        }
        for c in cols:
            self.tree.heading(c, text=headers[c])
            self.tree.column(c, width=160 if c not in ("email","occurred_at") else 240, anchor="w")
        self.tree.pack(fill="both", expand=True)

        self.reload()

    def clear(self):
        self.v_period.set("Custom")
        self.v_start.set(""); self.v_end.set("")
        self.reload()

    def _compute_dates(self):
        today = datetime.now().date()
        p = self.v_period.get()
        if p == "Day":
            start = end = today
        elif p == "Week":
            start = today - timedelta(days=today.weekday())   # Monday
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

    def reload(self):
        for i in self.tree.get_children(): self.tree.delete(i)

        start, end = self._compute_dates()
        rows = fetch_user_inactive_history(self.user_id, start, end, limit=1000)

        total_active = 0
        for r in rows:
            ad = int(r.get("active_duration_seconds") or 0)
            total_active += ad
            self.tree.insert("", "end", values=(
                r["username"], r["email"], r["event_type"], str(r["occurred_at"]),
                seconds_to_hhmmss(ad)
            ))

        self.t_active.set(seconds_to_hhmmss(total_active))

        ot_sum = fetch_overtime_sum(self.user_id, start, end)
        self.t_overtime.set(seconds_to_hhmmss(ot_sum))

        INACTIVITY_THRESHOLD = 10
        inactive_est = len(rows) * INACTIVITY_THRESHOLD
        self.t_inactive.set(seconds_to_hhmmss(inactive_est))


class MediaDialog(tk.Toplevel):
    def __init__(self, master, user_id, user_name):
        super().__init__(master)
        self.title(f"Media — {user_name}")
        self.resizable(True, True); self.geometry("900x520"); self.grab_set()

        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True)

        # screenshots
        scr_tab = ttk.Frame(nb, padding=6); nb.add(scr_tab, text="Screenshots")
        cols1 = ("id","event_id","taken_at","mime","url")
        self.tree_scr = ttk.Treeview(scr_tab, columns=cols1, show="headings", height=10)
        for c in cols1:
            self.tree_scr.heading(c, text=c)
            self.tree_scr.column(c, width=140, anchor="w")
        self.tree_scr.pack(fill="both", expand=True)
        ttk.Button(scr_tab, text="Open selected", command=self.open_selected_screenshot)\
            .pack(pady=6, anchor="e")

        # recordings
        rec_tab = ttk.Frame(nb, padding=6); nb.add(rec_tab, text="Recordings")
        cols2 = ("id","event_id","recorded_at","duration","mime","url")
        self.tree_rec = ttk.Treeview(rec_tab, columns=cols2, show="headings", height=10)
        for c in cols2:
            self.tree_rec.heading(c, text=c)
            self.tree_rec.column(c, width=160 if c!="duration" else 100, anchor="w")
        self.tree_rec.pack(fill="both", expand=True)
        ttk.Button(rec_tab, text="Open selected", command=self.open_selected_recording)\
            .pack(pady=6, anchor="e")

        self.user_id = user_id
        self._reload_media()

    def _reload_media(self):
        for i in self.tree_scr.get_children(): self.tree_scr.delete(i)
        for i in self.tree_rec.get_children(): self.tree_rec.delete(i)

        scrs = fetch_screenshots_for_user(self.user_id, limit=200)
        for s in scrs:
            self.tree_scr.insert("", "end",
                                 values=(s["id"], s["event_id"], str(s["taken_at"]), s["mime"], s["url"]))

        recs = fetch_recordings_for_user(self.user_id, limit=100)
        for r in recs:
            self.tree_rec.insert("", "end",
                                 values=(r["id"], r["event_id"], str(r["recorded_at"]),
                                         r["duration_seconds"], r["mime"], r["url"]))

    def open_selected_screenshot(self):
        sel = self.tree_scr.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a screenshot row."); return
        url = self.tree_scr.item(sel[0])["values"][4]
        webbrowser.open(url)

    def open_selected_recording(self):
        sel = self.tree_rec.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a recording row."); return
        url = self.tree_rec.item(sel[0])["values"][5]
        webbrowser.open(url)


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
        # log to console
        print(tb)
        # and also show a message box so you don't miss it
        try:
            messagebox.showerror("Admin crashed", tb)
        except Exception:
            pass
        sys.exit(1)
