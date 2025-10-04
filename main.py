from backend.notify import send_email
from backend.config import ADMIN_BOOTSTRAP
from backend.auth import login, admin_create_user, hash_password
from backend.models import (
    init_tables, list_users, fetch_unnotified_inactive_events, mark_event_notified,
    fetch_user_inactive_history, fetch_screenshots_for_user, fetch_recordings_for_user,
    list_admin_emails,
    admin_update_user, admin_delete_user, fetch_overtime_sum, get_user_by_id,
)
import os
import sys
import traceback
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from plyer import notification
from PIL import Image, ImageOps, ImageDraw
import io
import urllib.request

try:
    from zoneinfo import ZoneInfo
    SHIFT_TZ = ZoneInfo("Asia/Karachi")
except Exception:
    import pytz
    SHIFT_TZ = pytz.timezone("Asia/Karachi")

# --- UI: CustomTkinter ---
import customtkinter as ctk

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


try:
    from backend.config import ALERT_RECIPIENTS
except Exception:
    ALERT_RECIPIENTS = []

# ✅ Avatar helpers: use backend.media_server if available, else provide a compatible fallback
try:
    # preferred path
    from backend.media_server import save_user_avatar_from_path, remove_user_avatar
except Exception:
    # --- Fallback implementation (uses your backend.config + backend.models) ---
    import os
    from shutil import copyfile
    from uuid import uuid4
    from urllib.parse import urljoin
    from backend.config import MEDIA_ROOT, MEDIA_BASE_URL
    try:
        from backend.config import MEDIA_AVATARS_DIR
    except Exception:
        MEDIA_AVATARS_DIR = os.path.join(MEDIA_ROOT, "avatars")

    def _ensure_media_dirs():
        os.makedirs(MEDIA_ROOT, exist_ok=True)
        os.makedirs(MEDIA_AVATARS_DIR, exist_ok=True)

    def save_user_avatar_from_path(user_id: int, file_path: str) -> str:
        """
        Copies the picked image to MEDIA_AVATARS_DIR, generates a public URL,
        writes users.image_url via admin_update_user, and returns the URL.
        """
        _ensure_media_dirs()
        ext = os.path.splitext(file_path)[1].lower() or ".png"
        fname = f"user_{user_id}_{uuid4().hex}{ext}"
        dest_path = os.path.join(MEDIA_AVATARS_DIR, fname)
        copyfile(file_path, dest_path)

        # Make a URL relative to MEDIA_ROOT and join with MEDIA_BASE_URL
        rel = os.path.relpath(dest_path, MEDIA_ROOT).replace("\\", "/")
        public_url = urljoin(MEDIA_BASE_URL.rstrip("/") + "/", rel)

        try:
            admin_update_user(user_id, image_url=public_url)
        except Exception:
            # not fatal for UI; the function still returns the URL
            pass
        return public_url

    def remove_user_avatar(user_id: int) -> None:
        """
        Looks up current users.image_url, deletes the local file if it lives
        under MEDIA_ROOT, then clears users.image_url.
        """
        _ensure_media_dirs()

        try:
            u = get_user_by_id(user_id) or {}
            url = (u.get("image_url") or "").strip()
            if url and url.startswith(MEDIA_BASE_URL.rstrip("/") + "/"):
                rel = url[len(MEDIA_BASE_URL.rstrip("/") + "/"):].lstrip("/")
                local_path = os.path.join(MEDIA_ROOT, rel.replace("/", os.sep))
                if os.path.isfile(local_path):
                    try:
                        os.remove(local_path)
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            admin_update_user(user_id, image_url=None)
        except Exception:
            pass


REFRESH_MS = 2000

# Colors
APP_NAME = "Mars Capital"
APP_AUMID = "Mars Capital"
APP_ICON = os.path.join(os.getcwd(), "assets", "mars.ico")
if not os.path.isfile(APP_ICON):
    APP_ICON = None

# Theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

APP_BG = ("#f5f7fb", "#0f1115")
BAR_BG = ("#ffffff", "#151922")
SIDEBAR_BG = ("#eef2f7", "#0f1624")
CARD_BG = ("#ffffff", "#1b2030")
MUTED_TX = ("#6b7280", "#9aa4b2")

TOTAL_ACTIVE_COLOR = "#22c55e"
TOTAL_INACTIVE_COLOR = "#ef4444"
TOTAL_OVERTIME_COLOR = "#3b82f6"

INACTIVE_ROW_BG = "#fee2e2"

# Set AppUserModelID (Windows) so toasts won’t say "Python"
if sys.platform.startswith("win"):
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            APP_AUMID)
    except Exception:
        pass
# Helper: avatar image utils


def _circle_crop(img: Image.Image, size=(96, 96)) -> Image.Image:
    img = img.convert("RGBA")
    img = ImageOps.fit(img, size, Image.LANCZOS)
    mask = Image.new("L", size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size[0], size[1]), fill=255)
    img.putalpha(mask)
    return img

# AVATAR: download or read image, supports http(s) and file paths


def _load_pil_from_source(src: str) -> Image.Image | None:
    if not src:
        return None
    try:
        if src.startswith("http://") or src.startswith("https://"):
            with urllib.request.urlopen(src, timeout=8) as r:
                data = r.read()
            return Image.open(io.BytesIO(data))
        # local file
        if os.path.exists(src):
            return Image.open(src)
    except Exception:
        return None
    return None

# AVATAR: create a default placeholder (initials bubble)


def _default_avatar(initials: str = "U", size=(96, 96)) -> Image.Image:
    bg = "#334155"  # slate-700
    fg = "#e2e8f0"  # slate-200
    img = Image.new("RGB", size, bg)
    mask = Image.new("L", size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size[0], size[1]), fill=255)
    img.putalpha(mask)

    # draw initials
    draw = ImageDraw.Draw(img)
    # heuristic font size
    s = int(size[0] * 0.38)
    try:
        # If you have a TTF available, you can load it; Pillow default may vary
        from PIL import ImageFont
        font = ImageFont.truetype("arial.ttf", s)
    except Exception:
        from PIL import ImageFont
        font = ImageFont.load_default()

    tw, th = draw.textbbox((0, 0), initials, font=font)[2:]
    draw.text(((size[0] - tw) / 2, (size[1] - th) / 2),
              initials, font=font, fill=fg)
    return img

# AVATAR: get initials from user dict


def _initials_from_user(u: dict) -> str:
    name = (u.get("name") or "").strip()
    if not name:
        name = (u.get("username") or "U").strip()
    parts = [p for p in name.split() if p]
    if not parts:
        return "U"
    if len(parts) == 1:
        return parts[0][0:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()

# AVATAR: build CTkImage for a user


def _build_ctk_avatar(u: dict, size=(96, 96)) -> ctk.CTkImage:
    src = (u.get("image_url") or "").strip()
    pil = _load_pil_from_source(src)
    if pil is None:
        pil = _default_avatar(_initials_from_user(u), size=size)
    circ = _circle_crop(pil, size=size)
    return ctk.CTkImage(light_image=circ, dark_image=circ, size=size)


def admin_notify(title, message, timeout=5):
    try:
        kw = {"title": title, "message": message,
              "timeout": timeout, "app_name": APP_NAME}
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

# Main Application (CustomTk)


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
        self.auto_refresh_enabled = False

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
        dash.set_admin_name(self.admin_user.get(
            "name") or self.admin_user.get("username") or "Admin")
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
                    notification.notify(
                        title="User Inactive", message=msg, timeout=4, app_name=APP_NAME)
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
            updated_users = list_users(
                search=text, status=status, hide_admin=True)
        except Exception as e:
            print("Poll error:", e)

        if updated_users is not None:
            self.frames["AdminDashboardFrame"].apply_user_delta(updated_users)

        self._schedule_poll()


# Login Frame (CustomTk)
class AdminLoginFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, corner_radius=0, fg_color=APP_BG)

        card = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        card.pack(expand=True, fill="x", padx=32, pady=32)

        ctk.CTkLabel(card, text="Admin Login", font=ctk.CTkFont(
            size=22, weight="bold")).pack(pady=(18, 6))

        self.login_id = tk.StringVar(value="")
        self.login_pwd = tk.StringVar(value="")

        form = ctk.CTkFrame(card, fg_color="transparent")
        form.pack(fill="x", padx=20, pady=8)

        ctk.CTkLabel(form, text="Username or Email").pack(anchor="w")
        self.e_user = ctk.CTkEntry(
            form, textvariable=self.login_id, placeholder_text="admin@example.com", height=40)
        self.e_user.pack(fill="x", pady=(2, 8))

        ctk.CTkLabel(form, text="Password").pack(anchor="w")
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", pady=(2, 12))
        self.e_pwd = ctk.CTkEntry(
            row, textvariable=self.login_pwd, show="•", placeholder_text="••••••••", height=40)
        self.e_pwd.pack(side="left", fill="x", expand=True)

        def toggle_pwd():
            self.e_pwd.configure(
                show="" if self.e_pwd.cget("show") == "•" else "•")
            btn_toggle.configure(
                text=("Hide" if self.e_pwd.cget("show") == "" else "Show"))
        btn_toggle = ctk.CTkButton(
            row, text="Show", width=72, command=toggle_pwd)
        btn_toggle.pack(side="left", padx=(8, 0))

        ctk.CTkButton(card, text="Login", height=42, command=self.do_login).pack(
            pady=(6, 18), padx=20, fill="x")

        # Footer brand
        foot = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        foot.pack(side="bottom", fill="x")
        ctk.CTkLabel(foot, text="Mars Capital", font=ctk.CTkFont(
            size=12, weight="bold")).pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(foot, text="Lead with discipline. Excellence follows.",
                     text_color=MUTED_TX).pack(side="right", padx=12, pady=6)

    def do_login(self):
        try:
            admin = login(self.login_id.get().strip(),
                          self.login_pwd.get().strip())
            if not admin:
                messagebox.showerror("Login failed", "Invalid credentials")
                return
            self.master.on_admin_logged_in(admin)
        except Exception as e:
            messagebox.showerror("Error", str(e))


# Dashboard (CustomTk)
class AdminDashboardFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, corner_radius=0, fg_color=APP_BG)

        self.admin_name = tk.StringVar(value="Admin")

        # ===== NAVBAR =====
        navbar = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        navbar.pack(side="top", fill="x")

        left = ctk.CTkFrame(navbar, fg_color="transparent")
        left.pack(side="left", padx=12, pady=8)
        ctk.CTkLabel(left, text="Mars Capital", font=ctk.CTkFont(
            size=16, weight="bold")).pack(anchor="w")

        middle = ctk.CTkFrame(navbar, fg_color="transparent")
        middle.pack(side="left", padx=16, pady=8)
        ctk.CTkLabel(middle, textvariable=self.admin_name,
                     text_color=MUTED_TX).pack(anchor="w")

        right = ctk.CTkFrame(navbar, fg_color="transparent")
        right.pack(side="right", padx=12, pady=8)
        ctk.CTkButton(right, text="Add User", width=100,
                      command=self.open_create_user).pack(side="left", padx=(0, 8))
        ctk.CTkButton(right, text="Logout", width=90,
                      command=self.master.logout).pack(side="left")

        # ===== TOTALS STRIP =====
        totals = ctk.CTkFrame(self, fg_color="transparent")
        totals.pack(fill="x", padx=12, pady=(8, 6))

        def make_total(parent, label, color):
            card = ctk.CTkFrame(parent, corner_radius=12, fg_color=CARD_BG)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            ctk.CTkLabel(inner, text=label,
                         text_color=MUTED_TX).pack(anchor="w")
            value_sv = tk.StringVar(value="0")
            lbl = ctk.CTkLabel(inner, textvariable=value_sv,
                               font=ctk.CTkFont(size=18, weight="bold"))
            lbl.configure(text_color=color)
            lbl.pack(anchor="w")
            return card, value_sv

        totals_row = ctk.CTkFrame(totals, fg_color="transparent")
        totals_row.pack(fill="x")

        card_a, self.total_active_sv = make_total(
            totals_row, "Active Users", TOTAL_ACTIVE_COLOR)
        card_i, self.total_inactive_sv = make_total(
            totals_row, "Inactive Users", TOTAL_INACTIVE_COLOR)
        card_o, self.total_overtime_sv = make_total(
            totals_row, "Overtime (today)", TOTAL_OVERTIME_COLOR)

        card_a.pack(side="left", fill="x", expand=True, padx=(0, 6))
        card_i.pack(side="left", fill="x", expand=True, padx=6)
        card_o.pack(side="left", fill="x", expand=True, padx=(6, 0))

        # ===== BODY LAYOUT =====
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=(6, 0))

        # Sidebar (filters)
        sidebar = ctk.CTkFrame(
            body, width=280, corner_radius=12, fg_color=SIDEBAR_BG)
        sidebar.pack(side="left", fill="y", padx=(0, 8))
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Search", font=ctk.CTkFont(
            size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12, 4))
        self.search_var = tk.StringVar()
        self.search_entry = ctk.CTkEntry(
            sidebar, textvariable=self.search_var, placeholder_text="Name, username, email…")
        self.search_entry.pack(fill="x", padx=12)

        ctk.CTkLabel(sidebar, text="Status", font=ctk.CTkFont(
            size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12, 4))
        self.status_var = tk.StringVar(value="Any")
        self.status_cb = ctk.CTkComboBox(sidebar, values=[
                                         "Any", "off", "active", "inactive"], variable=self.status_var, width=120)
        self.status_cb.pack(anchor="w", padx=12)

        btn_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(12, 8))
        ctk.CTkButton(btn_row, text="Search", command=self._do_search).pack(
            side="left", padx=(0, 6))
        ctk.CTkButton(btn_row, text="Clear",
                      command=self._clear_search).pack(side="left")

        # Content area (cards)
        content = ctk.CTkFrame(body, corner_radius=12, fg_color=CARD_BG)
        content.pack(side="left", fill="both", expand=True)

        # Scrollable canvas for cards
        container = ctk.CTkFrame(content, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=8, pady=8)

        self.canvas = tk.Canvas(container, highlightthickness=0,
                                bg=APP_BG[0] if ctk.get_appearance_mode() == "Light" else APP_BG[1])
        vscroll = ttk.Scrollbar(
            container, orient="vertical", command=self.canvas.yview)
        self.cards_frame = ctk.CTkFrame(self.canvas, fg_color="transparent")
        self.cards_frame.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=vscroll.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        # Footer
        foot = ctk.CTkFrame(self, fg_color=BAR_BG, corner_radius=0)
        foot.pack(side="bottom", fill="x")
        ctk.CTkLabel(foot, text="Mars Capital", font=ctk.CTkFont(
            size=12, weight="bold")).pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(foot, text="Work hard in silence; let success make the noise.", text_color=MUTED_TX)\
            .pack(side="right", padx=12, pady=6)

        self.user_cards = {}
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
        users_sorted = sorted(users, key=lambda x: (
            x.get("name") or "", x.get("username") or ""))

        for idx, u in enumerate(users_sorted):
            uid = u["id"]
            info = self.user_cards.get(uid)
            if info is None:
                card = ctk.CTkFrame(
                    self.cards_frame, corner_radius=12, fg_color=CARD_BG)

                # AVATAR: two-column layout inside card
                row = ctk.CTkFrame(card, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=10)

                # left avatar
                left = ctk.CTkFrame(row, fg_color="transparent")
                left.pack(side="left", padx=(0, 12))
                avatar_img = _build_ctk_avatar(u, size=(96, 96))
                avatar_lbl = ctk.CTkLabel(left, image=avatar_img, text="")
                avatar_lbl.pack()

                # right details
                right = ctk.CTkFrame(row, fg_color="transparent")
                right.pack(side="left", fill="x", expand=True)

                name_lbl = ctk.CTkLabel(
                    right, text=u["name"] or "", font=ctk.CTkFont(size=14, weight="bold"))
                name_lbl.pack(anchor="w")
                user_lbl = ctk.CTkLabel(
                    right, text=f"@{u['username']}", text_color=MUTED_TX)
                user_lbl.pack(anchor="w")
                dept_lbl = ctk.CTkLabel(
                    right, text=f"Dept: {u['department']}", text_color=MUTED_TX)
                dept_lbl.pack(anchor="w")
                status_lbl = ctk.CTkLabel(
                    right, text=f"Status: {u['status'].lower()}")
                color = {"active": "#22c55e", "inactive": "#ef4444",
                         "off": "#000000"}.get(u["status"].lower(), None)
                if color:
                    status_lbl.configure(text_color=color)
                status_lbl.pack(anchor="w", pady=(4, 0))

                # action row bottom, centered button
                btn_row = ctk.CTkFrame(card, fg_color="transparent")
                btn_row.pack(fill="x", padx=12, pady=(6, 12))
                ctk.CTkButton(
                    btn_row,
                    text="View Details",
                    command=lambda uid=uid, uname=u["name"] or u["username"]: self.open_details(
                        uid, uname),
                    width=160
                ).pack(anchor="center")  # center

                info = {
                    "frame": card,
                    "avatar_img": avatar_img,     # keep ref!
                    "avatar_lbl": avatar_lbl,
                    "name_lbl": name_lbl,
                    "user_lbl": user_lbl,
                    "dept_lbl": dept_lbl,
                    "status_lbl": status_lbl,
                }
                self.user_cards[uid] = info
            else:
                # tiny diffs + avatar refresh if URL changed
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
                color = {"active": "#22c55e", "inactive": "#ef4444",
                         "off": "#000000"}.get(u["status"].lower(), None)
                if color:
                    info["status_lbl"].configure(text_color=color)

                # AVATAR: if image_url changed or missing, rebuild
                try:
                    new_img = _build_ctk_avatar(u, size=(96, 96))
                    info["avatar_img"] = new_img
                    info["avatar_lbl"].configure(image=new_img)
                except Exception:
                    pass

            r, c = divmod(idx, cols)
            self.user_cards[uid]["frame"].grid(
                row=r, column=c, padx=8, pady=8, sticky="nsew")

        # column weights
        for i in range(cols):
            self.cards_frame.grid_columnconfigure(i, weight=1, minsize=490)

        # ---- totals strip update ----
        active_count = sum(1 for u in users if (
            u.get("status") or "").lower() == "active")
        inactive_count = sum(1 for u in users if (
            u.get("status") or "").lower() == "inactive")

        # Overtime today total across visible users
        today = datetime.now(SHIFT_TZ).date()  # <-- TZ fix
        start = str(today)
        end = str(today)
        overtime_total = 0
        try:
            for u in users:
                try:
                    overtime_total += int(
                        fetch_overtime_sum(u["id"], start, end) or 0)
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


# Dialogs (CustomTk versions)

class CreateUserDialog(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Create User")
        self.grab_set()
        self.resizable(True, True)
        self.configure(fg_color=BAR_BG)

        # Wider default size + guardrails
        self.geometry("320x600")
        self.minsize(380, 600)

        p = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        p.pack(fill="both", expand=True, padx=16, pady=16)
        p.configure(width=720)

        # --- variables ---
        self.v_username = tk.StringVar()
        self.v_name = tk.StringVar()
        self.v_dept = tk.StringVar()
        self.v_email = tk.StringVar()
        self.v_password = tk.StringVar()
        self.v_password2 = tk.StringVar()
        self.v_shift_start = tk.StringVar(value="09:00:00")
        self.v_shift_end = tk.StringVar(value="18:00:00")

        # AVATAR: store temp picked file and preview
        self.v_avatar_path = tk.StringVar(value="")
        self._avatar_preview_img = None  # keep CTkImage reference

        # keep entry widgets for highlighting/focus
        self.inputs = {}

        def row(label, var, key, is_pwd=False):
            ctk.CTkLabel(p, text=label).pack(anchor="w", pady=(6, 0))
            e = ctk.CTkEntry(
                p,
                textvariable=var,
                show="•" if is_pwd else None,
                placeholder_text=label,
                height=38,
            )
            e.pack(fill="x")
            self.inputs[key] = e
            return e

        row("Username", self.v_username, "username")
        row("Name", self.v_name, "name")
        row("Department", self.v_dept, "dept")
        row("Email", self.v_email, "email")
        row("Password", self.v_password, "password", is_pwd=True)
        row("Confirm Password", self.v_password2, "password2", is_pwd=True)
        row("Shift Start (HH:MM:SS)", self.v_shift_start, "shift_start")
        row("Shift End (HH:MM:SS)", self.v_shift_end, "shift_end")

        # AVATAR: picker + preview
        avatar_row = ctk.CTkFrame(p, fg_color="transparent")
        avatar_row.pack(fill="x", pady=(8, 4))
        ctk.CTkLabel(avatar_row, text="Avatar (optional)").pack(side="left")
        ctk.CTkButton(avatar_row, text="Choose Image",
                      command=self._pick_avatar, width=120).pack(side="right")

        # preview
        self.avatar_preview = ctk.CTkLabel(p, text="")
        self.avatar_preview.pack(pady=(0, 6))

        ctk.CTkButton(p, text="Create", command=self.do_create,
                      height=40).pack(pady=12, fill="x")

        self.after(10, self._center)

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw//2 - w//2)}+{(sh//2 - h//2)}")

    # ---- helpers ----
    def _mark_error(self, entry: ctk.CTkEntry):
        """Show a red border briefly, then restore to a neutral color."""
        try:
            entry.configure(border_color="#ef4444", border_width=2)

            def _restore():
                try:
                    entry.configure(border_color=(
                        "#D1D5DB", "#374151"), border_width=1)
                except Exception:
                    pass
            self.after(1500, _restore)
        except Exception:
            pass

    @staticmethod
    def _circle_crop(pil_img: Image.Image, size=(96, 96)) -> Image.Image:
        pil_img = pil_img.convert("RGBA")
        pil_img = ImageOps.fit(pil_img, size, Image.LANCZOS)
        mask = Image.new("L", size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, size[0], size[1]), fill=255)
        pil_img.putalpha(mask)
        return pil_img

    # ---- avatar picking + preview ----
    def _pick_avatar(self):
        path = filedialog.askopenfilename(
            title="Select Avatar Image",
            filetypes=[
                ("Image Files", "*.png;*.jpg;*.jpeg;*.webp;*.gif"), ("All Files", "*.*")]
        )
        if not path:
            return
        self.v_avatar_path.set(path)
        try:
            pil = Image.open(path)
            circ = self._circle_crop(pil, size=(96, 96))
            img = ctk.CTkImage(
                light_image=circ, dark_image=circ, size=(96, 96))
            self._avatar_preview_img = img
            self.avatar_preview.configure(image=img, text="")
        except Exception as e:
            messagebox.showerror("Avatar", f"Could not load image: {e}")

    # ---- creation logic ----
    def do_create(self):
        # Trimmed values
        vals = {
            "username": (self.v_username.get().strip(), "Username"),
            "name": (self.v_name.get().strip(), "Name"),
            "dept": (self.v_dept.get().strip(), "Department"),
            "email": (self.v_email.get().strip(), "Email"),
            "password": (self.v_password.get().strip(), "Password"),
            "password2": (self.v_password2.get().strip(), "Confirm Password"),
            "shift_start": (self.v_shift_start.get().strip(), "Shift Start (HH:MM:SS)"),
            "shift_end": (self.v_shift_end.get().strip(), "Shift End (HH:MM:SS)"),
        }

        # 1) required fields
        missing_keys = [k for k, (v, _) in vals.items() if not v]
        if missing_keys:
            for i, k in enumerate(missing_keys):
                self._mark_error(self.inputs[k])
                if i == 0:
                    try:
                        self.inputs[k].focus_set()
                    except Exception:
                        pass
            missing_labels = ", ".join(vals[k][1] for k in missing_keys)
            messagebox.showerror(
                "Validation", f"All fields are required. Please fill: {missing_labels}")
            return

        # 2) passwords must match
        if vals["password"][0] != vals["password2"][0]:
            self._mark_error(self.inputs["password"])
            self._mark_error(self.inputs["password2"])
            try:
                self.inputs["password"].focus_set()
            except Exception:
                pass
            messagebox.showerror("Validation", "Passwords do not match.")
            return

        try:
            # Create user with your existing backend call
            admin_create_user(
                vals["username"][0],
                vals["name"][0],
                vals["dept"][0],
                vals["email"][0],
                vals["password"][0],
                shift_start_time=vals["shift_start"][0],
                shift_end_time=vals["shift_end"][0],
            )

            # If avatar picked, attach it to the newly created user
            picked = self.v_avatar_path.get().strip()
            if picked:
                try:
                    # Find the just-created user by exact username
                    created = list_users(
                        search=vals["username"][0], status=None, hide_admin=True) or []
                    target = None
                    for u in created:
                        if u.get("username") == vals["username"][0]:
                            target = u
                            break
                    if not target and created:
                        target = created[0]

                    if target:
                        url = save_user_avatar_from_path(target["id"], picked)
                        # force-write image_url in case helper didn't persist it
                        try:
                            admin_update_user(target["id"], image_url=url)
                        except Exception:
                            pass
                except Exception as e:
                    print("Avatar save error (create):", e)

            messagebox.showinfo("Done", "User created")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", str(e))


def _mark_error(self, entry: ctk.CTkEntry):
    try:
        entry.configure(border_color="#ef4444", border_width=2)

        def _restore():
            try:
                entry.configure(border_color=(
                    "#D1D5DB", "#374151"), border_width=1)
            except Exception:
                pass
        self.after(1500, _restore)
    except Exception:
        pass


class UpdateUserDialog(ctk.CTkToplevel):
    def __init__(self, master, user: dict):
        super().__init__(master)
        self.title(f"Update User — @{user.get('username')}")
        self.grab_set()
        self.resizable(True, True)
        self.configure(fg_color=BAR_BG)

        self.user = user
        self.geometry("360x640")
        self.minsize(380, 640)

        # OUTER CARD
        card = ctk.CTkFrame(self, corner_radius=12, fg_color=CARD_BG)
        card.pack(fill="both", expand=True, padx=16, pady=16)
        card.configure(width=720)

        # SCROLLABLE BODY to avoid layout conflicts/overflow
        p = ctk.CTkScrollableFrame(card, fg_color="transparent")
        p.pack(fill="both", expand=True)

        # vars (pre-fill with existing)
        self.v_username = tk.StringVar(value=user.get("username", ""))
        self.v_name = tk.StringVar(value=user.get("name", ""))
        self.v_dept = tk.StringVar(value=user.get("department", ""))
        self.v_email = tk.StringVar(value=user.get("email", ""))
        self.v_status = tk.StringVar(value=(user.get("status") or "active"))
        self.v_shift_start = tk.StringVar(
            value=user.get("shift_start_time") or "09:00:00")
        self.v_shift_end = tk.StringVar(
            value=user.get("shift_end_time") or "18:00:00")

        # password (optional; leave blank to keep)
        self.v_pass1 = tk.StringVar(value="")
        self.v_pass2 = tk.StringVar(value="")

        # AVATAR: path for replacement
        self.v_avatar_path = tk.StringVar(value="")
        self._avatar_preview_img = None

        # Header / Avatar preview
        header = ctk.CTkFrame(p, fg_color="transparent")
        header.pack(fill="x", pady=(6, 10))
        ctk.CTkLabel(header, text="Current Avatar / Preview").pack(anchor="w")

        curr = _build_ctk_avatar(user, size=(96, 96))
        self.avatar_preview = ctk.CTkLabel(header, image=curr, text="")
        self.avatar_preview.pack(pady=(4, 6))

        # helper to build rows
        def row(parent, label, var, readonly=False, is_pwd=False, ph=None, show_label=True):
            if show_label:
                ctk.CTkLabel(parent, text=label).pack(anchor="w", pady=(4, 0))
            e = ctk.CTkEntry(
                parent,
                textvariable=var,
                height=38,
                show="•" if is_pwd else None,
                placeholder_text=ph or label
            )
            if readonly:
                e.configure(state="readonly")
            e.pack(fill="x")
            return e

        row(p, "Username", self.v_username, readonly=True)
        row(p, "Name", self.v_name)
        row(p, "Department", self.v_dept)
        row(p, "Email", self.v_email)
        row(p, "Shift Start (HH:MM:SS)", self.v_shift_start)
        row(p, "Shift End (HH:MM:SS)", self.v_shift_end)

        # Password section (single labels; avoid duplicates)
        ctk.CTkLabel(p, text="New Password (leave blank to keep)").pack(
            anchor="w", pady=(10, 0))
        row(p, "New Password", self.v_pass1, is_pwd=True,
            ph="New Password", show_label=False)
        ctk.CTkLabel(p, text="Confirm Password").pack(anchor="w", pady=(6, 0))
        row(p, "Confirm Password", self.v_pass2, is_pwd=True,
            ph="Confirm Password", show_label=False)

        # AVATAR: choose/clear
        avatar_row = ctk.CTkFrame(p, fg_color="transparent")
        avatar_row.pack(fill="x", pady=(10, 2))
        ctk.CTkButton(avatar_row, text="Choose New Avatar",
                      command=self._pick_avatar, width=160).pack(side="left")
        ctk.CTkButton(avatar_row, text="Remove Avatar",
                      command=self._remove_avatar, width=140).pack(side="right")

        # save
        ctk.CTkButton(p, text="Save Changes", command=self._save,
                      height=40).pack(pady=12, fill="x")

        self.after(10, self._center)

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw//2 - w//2)}+{(sh//2 - h//2)}")

    def _pick_avatar(self):
        path = filedialog.askopenfilename(
            title="Select New Avatar Image",
            filetypes=[
                ("Image Files", "*.png;*.jpg;*.jpeg;*.webp;*.gif"), ("All Files", "*.*")]
        )
        if not path:
            return
        self.v_avatar_path.set(path)
        try:
            pil = Image.open(path)
            circ = _circle_crop(pil, size=(96, 96))
            img = ctk.CTkImage(
                light_image=circ, dark_image=circ, size=(96, 96))
            self._avatar_preview_img = img
            self.avatar_preview.configure(image=img)
        except Exception as e:
            messagebox.showerror("Avatar", f"Could not load image: {e}")

    def _remove_avatar(self):
        try:
            remove_user_avatar(self.user["id"])
            img = _build_ctk_avatar(
                {"name": self.v_name.get(), "username": self.v_username.get(),
                 "image_url": ""},
                size=(96, 96)
            )
            self._avatar_preview_img = img
            self.avatar_preview.configure(image=img)
            messagebox.showinfo("Avatar", "Avatar removed.")
        except Exception as e:
            messagebox.showerror("Avatar", str(e))

    def _save(self):
        try:
            # validate optional password
            p1 = (self.v_pass1.get() or "").strip()
            p2 = (self.v_pass2.get() or "").strip()
            if p1 or p2:
                if p1 != p2:
                    messagebox.showerror(
                        "Validation", "Passwords do not match.")
                    return
                if len(p1) < 6:
                    messagebox.showerror(
                        "Validation", "Password must be at least 6 characters.")
                    return

            # Update core fields
            admin_update_user(
                self.user["id"],
                name=self.v_name.get().strip(),
                department=self.v_dept.get().strip(),
                email=self.v_email.get().strip(),
                status=self.v_status.get().strip(),
                shift_start_time=self.v_shift_start.get().strip(),
                shift_end_time=self.v_shift_end.get().strip(),
                **({"password_hash": hash_password(p1)} if p1 else {})
            )

            # Avatar update if chosen
            picked = self.v_avatar_path.get().strip()
            if picked:
                try:
                    save_user_avatar_from_path(self.user["id"], picked)
                except Exception as e:
                    print("Avatar save error (update):", e)

            messagebox.showinfo("Done", "User updated")
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

        # NEW: keep an auto-refresh job handle
        self._hist_auto_job = None
        self._media_tick = 0  # refresh media less frequently

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

        # Keep label references so we can update them later
        self.over_name_lbl = ctk.CTkLabel(
            over_card, text=f"Name: {fresh.get('name') or ''}")
        self.over_name_lbl.pack(anchor="w", padx=12, pady=(10, 0))

        self.over_user_lbl = ctk.CTkLabel(
            over_card, text=f"Username: @{fresh.get('username') or ''}", text_color=MUTED_TX
        )
        self.over_user_lbl.pack(anchor="w", padx=12)

        self.over_dept_lbl = ctk.CTkLabel(
            over_card, text=f"Department: {fresh.get('department') or ''}", text_color=MUTED_TX
        )
        self.over_dept_lbl.pack(anchor="w", padx=12, pady=(0, 10))

        st = (fresh.get("status") or "").lower()
        status_color = {"active": "#22c55e",
                        "inactive": "#ef4444", "off": "#000000"}.get(st, None)
        self.over_status_lbl = ctk.CTkLabel(
            over_card, text=f"Status: {st}", text_color=status_color)
        self.over_status_lbl.pack(anchor="w", padx=12, pady=(0, 10))

        # Actions row (the 4 buttons live here)
        actions = ctk.CTkFrame(tab_over, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(actions, text="History", width=120, command=lambda: nb.select(
            tab_over_history)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Media", width=120, command=lambda: nb.select(
            tab_media)).pack(side="left", padx=8)
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
        side = ctk.CTkFrame(hist_body, width=260,
                            corner_radius=12, fg_color=SIDEBAR_BG)
        side.pack(side="left", fill="y", padx=(0, 8))
        side.pack_propagate(False)

        ctk.CTkLabel(side, text="Filters", font=ctk.CTkFont(size=14, weight="bold"))\
            .pack(anchor="w", padx=12, pady=(12, 6))
        self.v_period = tk.StringVar(value="Custom")
        ctk.CTkLabel(side, text="Period").pack(anchor="w", padx=12)
        ctk.CTkComboBox(side, values=["Day", "Week", "Month", "Custom"], variable=self.v_period, width=120)\
            .pack(anchor="w", padx=12, pady=(0, 6))

        self.v_start = tk.StringVar()
        self.v_end = tk.StringVar()

        ctk.CTkLabel(side, text="Start (YYYY-MM-DD)").pack(anchor="w", padx=12)
        ctk.CTkEntry(side, textvariable=self.v_start, placeholder_text="YYYY-MM-DD")\
            .pack(fill="x", padx=12, pady=(0, 6))
        ctk.CTkLabel(side, text="End (YYYY-MM-DD)").pack(anchor="w", padx=12)
        ctk.CTkEntry(side, textvariable=self.v_end, placeholder_text="YYYY-MM-DD")\
            .pack(fill="x", padx=12, pady=(0, 6))

        btns = ctk.CTkFrame(side, fg_color="transparent")
        btns.pack(anchor="w", padx=12, pady=(8, 12))
        ctk.CTkButton(btns, text="Search", command=self._hist_reload).pack(
            side="left", padx=(0, 6))
        ctk.CTkButton(btns, text="Clear",
                      command=self._hist_clear).pack(side="left")

        # Totals strip
        totals = ctk.CTkFrame(hist_body, fg_color="transparent")
        totals.pack(side="top", fill="x", padx=8, pady=(0, 6))
        
        def make_total(parent, label, color):
            card = ctk.CTkFrame(parent, corner_radius=12, fg_color=CARD_BG)
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            ctk.CTkLabel(inner, text=label,
                         text_color=MUTED_TX).pack(anchor="w")
            value_sv = tk.StringVar(value="00:00:00")
            lbl = ctk.CTkLabel(inner, textvariable=value_sv,
                               font=ctk.CTkFont(size=16, weight="bold"))
            lbl.configure(text_color=color)
            lbl.pack(anchor="w")
            return card, value_sv

        totals_row = ctk.CTkFrame(totals, fg_color="transparent")
        totals_row.pack(fill="x")
        card_a, self.t_active_sv = make_total(
            totals_row, "Total Active", "#10b981")
        card_i, self.t_inactive_sv = make_total(
            totals_row, "Total Inactive", "#ef4444")
        card_tot, self.t_total_sv = make_total(
            totals_row, "Today Total", "#111827")
        # NEW: overtime in period
        card_ot, self.t_overtime_sv = make_total(
            totals_row, "Overtime (period)", "#3b82f6")

        card_a.pack(side="left", fill="x", expand=True, padx=(0, 6))
        card_i.pack(side="left", fill="x", expand=True, padx=6)
        card_tot.pack(side="left", fill="x", expand=True, padx=6)
        card_ot.pack(side="left", fill="x", expand=True, padx=(6, 0))

        

        # Table area
        table_wrap = ctk.CTkFrame(
            hist_body, corner_radius=12, fg_color=CARD_BG)
        table_wrap.pack(fill="both", expand=True, padx=8, pady=4)

        cols = ("username", "email", "event", "occurred_at", "active_duration")
        self.tree_hist = ttk.Treeview(
            table_wrap, columns=cols, show="headings")
        headers = {
            "username": "username", "email": "email", "event": "event",
            "occurred_at": "occurred_at", "active_duration": "active_duration"
        }
        for c in cols:
            self.tree_hist.heading(c, text=headers[c])
            self.tree_hist.column(c, width=170 if c not in (
                "email", "occurred_at") else 240, anchor="w")
        self.tree_hist.pack(fill="both", expand=True, padx=6, pady=6)

        # tag style for inactive events
        self.tree_hist.tag_configure(
            "inactive_row", background=INACTIVE_ROW_BG)

        # initial load
        self._hist_reload()

        # ========== Media ==========
        tab_media = ctk.CTkFrame(nb, fg_color=APP_BG)
        nb.add(tab_media, text="Media")

        # Screenshots (simple columns: taken_at, url)
        scr_card = ctk.CTkFrame(tab_media, corner_radius=12, fg_color=CARD_BG)
        scr_card.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        ctk.CTkLabel(scr_card, text="Screenshots", font=ctk.CTkFont(size=14, weight="bold"))\
            .pack(anchor="w", padx=10, pady=(10, 0))

        self.tree_scr = ttk.Treeview(scr_card, columns=(
            "taken_at", "url"), show="headings", height=8)
        self.tree_scr.heading("taken_at", text="taken_at")
        self.tree_scr.heading("url", text="url")
        self.tree_scr.column("taken_at", width=220, anchor="w")
        self.tree_scr.column("url", width=600, anchor="w")
        self.tree_scr.pack(fill="both", expand=True, padx=10, pady=(6, 6))
        ctk.CTkButton(scr_card, text="Open selected", command=self.open_selected_screenshot)\
            .pack(anchor="e", padx=10, pady=(0, 10))

        # Recordings (simple columns: recorded_at, url)
        rec_card = ctk.CTkFrame(tab_media, corner_radius=12, fg_color=CARD_BG)
        rec_card.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        ctk.CTkLabel(rec_card, text="Recordings", font=ctk.CTkFont(size=14, weight="bold"))\
            .pack(anchor="w", padx=10, pady=(10, 0))

        self.tree_rec = ttk.Treeview(rec_card, columns=(
            "recorded_at", "url"), show="headings", height=8)
        self.tree_rec.heading("recorded_at", text="recorded_at")
        self.tree_rec.heading("url", text="url")
        self.tree_rec.column("recorded_at", width=220, anchor="w")
        self.tree_rec.column("url", width=600, anchor="w")
        self.tree_rec.pack(fill="both", expand=True, padx=10, pady=(6, 6))
        ctk.CTkButton(rec_card, text="Open selected", command=self.open_selected_recording)\
            .pack(anchor="e", padx=10, pady=(0, 10))

        # load media
        self._reload_media()

        # ========== Update ==========
        tab_update = ctk.CTkFrame(nb, fg_color=APP_BG)
        nb.add(tab_update, text="Update")

        fresh = get_user_by_id(self.user_id) or {}
        ctk.CTkLabel(tab_update, text="Update User", font=ctk.CTkFont(size=16, weight="bold"))\
            .pack(anchor="w", padx=12, pady=(12, 0))
        ctk.CTkButton(
            tab_update,
            text="Open Update Form",
            command=lambda: self._open_update_then_refresh(nb, tab_update)
        ).pack(anchor="w", padx=12, pady=(8, 12))

        # ========= NEW: start auto-refresh loop (History + Overview + Media cadence) =========
        # will refresh while this dialog is open
        self._media_tick = 0
        self._hist_auto_job = None
        self._schedule_hist_autorefresh()
        # cancel the timer when dialog is destroyed
        self.bind("<Destroy>", lambda _e: self._cancel_hist_autorefresh())

    # ---- NEW: periodic auto-refresh for History/Overview/Media ----
    def _schedule_hist_autorefresh(self):
        """Refresh History totals/table + Overview labels every 2s, Media every ~10s."""
        def _tick():
            try:
                # History totals + table (this also updates overtime via fetch_overtime_sum)
                self._hist_reload()
                # Overview labels (status/name/etc.) from DB
                self._refresh_overview_labels()
                # Media less frequently to avoid heavy IO
                self._media_tick = (self._media_tick + 1) % 5  # every ~10s if tick is 2s
                if self._media_tick == 0:
                    self._reload_media()
            except Exception:
                # swallow errors to keep the loop alive
                pass
            finally:
                self._hist_auto_job = self.after(2000, _tick)  # 2s cadence
        # kick it off
        self._hist_auto_job = self.after(2000, _tick)

    def _cancel_hist_autorefresh(self):
        try:
            if getattr(self, "_hist_auto_job", None):
                self.after_cancel(self._hist_auto_job)
        except Exception:
            pass
        self._hist_auto_job = None

    # ---- refresh overview labels from DB ----
    def _refresh_overview_labels(self):
        try:
            fresh = get_user_by_id(self.user_id) or {}
        except Exception:
            fresh = {}
        self.over_name_lbl.configure(text=f"Name: {fresh.get('name') or ''}")
        self.over_user_lbl.configure(text=f"Username: @{fresh.get('username') or ''}")
        self.over_dept_lbl.configure(text=f"Department: {fresh.get('department') or ''}")
        st = (fresh.get("status") or "").lower()
        status_color = {"active": "#22c55e", "inactive": "#ef4444", "off": "#000000"}.get(st, None)
        self.over_status_lbl.configure(text=f"Status: {st}", text_color=status_color)

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
        # Use Asia/Karachi to derive Day/Week/Month ranges
        today = datetime.now(SHIFT_TZ).date()  # <-- TZ fix
        p = self.v_period.get()
        if p == "Day":
            start = end = today
        elif p == "Week":
            start = today - timedelta(days=today.weekday())
            end = start + timedelta(days=6)
        elif p == "Month":
            start = today.replace(day=1)
            if start.month == 12:
                end = start.replace(year=start.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                end = start.replace(month=start.month + 1, day=1) - timedelta(days=1)
        else:
            s = self.v_start.get().strip() or None
            e = self.v_end.get().strip() or None
            return (s, e)
        return (str(start), str(end))

    # ---- History tab logic ----
    def _hist_clear(self):
        self.v_period.set("Custom")
        self.v_start.set("")
        self.v_end.set("")
        self._hist_reload()

    def _hist_reload(self):
        # clear table
        for i in self.tree_hist.get_children():
            self.tree_hist.delete(i)

        start, end = self._compute_dates()
        rows = fetch_user_inactive_history(self.user_id, start, end, limit=1500)

        # exact totals from events
        total_active = 0     # sum of durations on 'inactive' events (= active streaks that ended)
        total_inactive = 0   # sum of durations on 'active' events (= inactive streaks that ended)

        for r in rows:
            ad = int(r.get("active_duration_seconds") or 0)
            ev = (r.get("event_type") or "").lower()

            if ev == "inactive":
                total_active += ad
            elif ev == "active":
                total_inactive += ad

            vals = (r["username"], r["email"], r["event_type"], str(r["occurred_at"]), seconds_to_hhmmss(ad))
            tag = "inactive_row" if ev == "inactive" else ""
            self.tree_hist.insert("", "end", values=vals, tags=(tag,))

        # update totals strip
        self.t_active_sv.set(seconds_to_hhmmss(total_active))
        self.t_inactive_sv.set(seconds_to_hhmmss(total_inactive))
        self.t_total_sv.set(seconds_to_hhmmss(total_active + total_inactive))

        # NEW: overtime sum for this user & period
        ot_sum = fetch_overtime_sum(self.user_id, start, end)
        self.t_overtime_sv.set(seconds_to_hhmmss(int(ot_sum)))

    def _reload_media(self):
        # screenshots
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
            # stay on same tab and refresh this dialog's data
            nb.select(current_tab)
            self._refresh_overview_labels()
            self._hist_reload()
            self._reload_media()
            # Also refresh the dashboard cards immediately
            try:
                # self.master is AdminDashboardFrame
                self.master._do_search()
            except Exception:
                pass



# Launcher
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
