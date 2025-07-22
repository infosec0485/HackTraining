import customtkinter as ctk
import subprocess
import threading
import requests
import time
import os, csv, sys
from jinja2 import Environment, FileSystemLoader
from tkinter import filedialog
from datetime import datetime
from PIL import Image, ImageTk
import tkinter as tk
import webbrowser
import random

# ───────── 설정 ─────────
PYTHON_PATH = r"E:\phishing_trainer\venv\Scripts\python.exe"
SERVER_HOST = "192.168.100.81"
SERVER_PORT = 8000
SERVER_BASE = f"http://{SERVER_HOST}:{SERVER_PORT}"

# ───────── 경로 헬퍼 ─────────
def resource_path(relative: str) -> str:
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)

# ───────── 상태 변수 ─────────
server_process = None
running = False
csv_path = "spam.csv"
csv_total = 0
training_mode = 2   # 기본 2단계

# ───────── GUI 초기화 ─────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.title("Phishing Trainer 제어판")
app.geometry("480x800")

# ───────── 템플릿 로딩 ─────────
template_dir = resource_path("templates")
env = Environment(loader=FileSystemLoader(template_dir))
template_files = [f for f in os.listdir(template_dir) if f.endswith(".html")]
selected_template = ctk.StringVar(
    value=template_files[0] if template_files else "(없음)"
)
selected_info_template = ctk.StringVar(
    value=template_files[0] if template_files else "(없음)"
)

# ───────── 로그창 ─────────
log_box = ctk.CTkTextbox(app, width=440, height=200, font=("맑은 고딕", 11))
def log(msg: str):
    log_box.insert("end", f"{msg}\n")
    log_box.see("end")

# ───────── 서버 상태 ─────────
status_label = ctk.CTkLabel(app, text="서버 중지됨", text_color="red", font=("맑은 고딕", 16))
status_label.pack(pady=10)

# ───────── 서버 제어 그룹 ─────────
server_frame = ctk.CTkFrame(app)
server_frame.pack(pady=5)

# (row 0) 서버 시작/중지
ctk.CTkButton(server_frame, text="서버 시작",
              command=lambda: start_server()).grid(row=0, column=0, padx=5)
ctk.CTkButton(server_frame, text="서버 중지",
              command=lambda: stop_server()).grid(row=0, column=1, padx=5)

# 훈련 모드 토글 함수
def set_mode(mode: int):
    global training_mode
    training_mode = mode
    if mode == 2:
        step2_btn.configure(state="disabled")
        step3_btn.configure(state="normal")
        info_template_menu.configure(state="disabled")
    else:
        step2_btn.configure(state="normal")
        step3_btn.configure(state="disabled")
        info_template_menu.configure(state="normal")
    mode_label.configure(text=f"현재 모드: {mode}단계")
    log(f"🔧 훈련 모드 설정: {mode}단계")

# (row 1) 2단계 / 3단계 버튼
step2_btn = ctk.CTkButton(server_frame, text="2단계(열람/감염)",
                          width=200, command=lambda: set_mode(2))
step3_btn = ctk.CTkButton(server_frame, text="3단계(열람/개인정보/감염)",
                          width=200, command=lambda: set_mode(3))
step2_btn.grid(row=1, column=0, padx=5, pady=3)
step3_btn.grid(row=1, column=1, padx=5, pady=3)
step2_btn.configure(state="disabled")          # 기본 2단계
mode_label = ctk.CTkLabel(server_frame, text="현재 모드: 2단계")
mode_label.grid(row=2, column=0, columnspan=2, pady=(0,5))

ctk.CTkLabel(app, text="──────────────────────────────────────",
             text_color="gray").pack(pady=5)

# ───────── 수신자·템플릿 선택 ─────────
input_frame = ctk.CTkFrame(app)
input_frame.pack(pady=5)
ctk.CTkButton(input_frame, text="📁 수신자 CSV 선택",
              command=lambda: select_csv()).pack(pady=3)
csv_label = ctk.CTkLabel(input_frame, text="📄 대상자 수: 알 수 없음",
                         font=("맑은 고딕", 12))
csv_label.pack()

ctk.CTkLabel(input_frame, text="📁 메일 템플릿 선택",
             font=("맑은 고딕", 13)).pack(pady=(10,2))
template_menu = ctk.CTkOptionMenu(input_frame, values=template_files,
                                  variable=selected_template)
template_menu.pack(pady=(0,5))
ctk.CTkLabel(input_frame, text="📁 개인정보 입력 템플릿",
             font=("맑은 고딕", 13)).pack(pady=(10,2))
info_template_menu = ctk.CTkOptionMenu(input_frame, values=template_files,
                                       variable=selected_info_template)
info_template_menu.pack(pady=(0,5))
info_template_menu.configure(state="disabled")
ctk.CTkButton(input_frame, text="템플릿 미리보기",
              command=lambda: preview_template()).pack(pady=5)

ctk.CTkButton(input_frame, text="메일 발송 시작",
              command=lambda: send_emails()).pack(pady=5)

# ───────── 감염현황·보고서 그룹 ─────────
status_frame = ctk.CTkFrame(app)
status_frame.pack(pady=5)
ctk.CTkButton(status_frame, text="📊 감염 현황 보기",
              command=lambda: show_training_status_table()).pack(pady=3)
ctk.CTkLabel(app, text="──────────────────────────────────────",
             text_color="gray").pack(pady=5)
ctk.CTkButton(status_frame, text="📁 결과 보고서 저장",
              command=lambda: export_final_report()).pack(pady=3)

# ───────── 훈련 제어 그룹 ─────────
control_frame = ctk.CTkFrame(app)
control_frame.pack(pady=5)
ctk.CTkButton(control_frame, text="🆕 새 훈련 시작",
              command=lambda: reset_training()).pack(pady=3)
ctk.CTkButton(control_frame, text="📥 훈련 종료 및 잠금",
              command=lambda: end_training()).pack(pady=3)

# ───────── 감염자 수 ─────────
infection_label = ctk.CTkLabel(app, text="🦠 감염자 수: --명",
                               font=("맑은 고딕", 13))
infection_label.pack(pady=8)

# ───────── 로그 박스 ─────────
log_box.pack(padx=10, pady=10)

# ───────── 로고 ─────────
try:
    logo = Image.open(resource_path("logo.png")).convert("RGBA").resize((160, 40))
    logo_img = ImageTk.PhotoImage(logo)
    logo_label = tk.Label(app, image=logo_img, bg=app.cget("bg"))
    logo_label.image = logo_img
    logo_label.place(relx=0.5, rely=1.0, x=0, y=-60, anchor="s")
except Exception:
    log("🔔 로고 로드 실패")

# ───────── 서명 ─────────
signature_text = "Powered by 윤지환 | 정보보안부문 · 2025.06.20"
author_label = ctk.CTkLabel(app, text=signature_text,
                            font=("맑은 고딕", 10), anchor="e",
                            justify="right")
author_label.place(relx=1.0, rely=1.0, x=-10, y=-10, anchor="se")

# ───────── 기능 함수 ─────────
def preview_template():
    template_name = selected_template.get()
    if not template_name.endswith(".html"):
        log("❌ HTML 템플릿만 미리보기 가능")
        return
    try:
        preview_name = "홍길동"
        preview_uuid = "0000-0000-0000-0000"
        if os.path.exists(csv_path):
            with open(csv_path, encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
                if reader:
                    user = random.choice(reader)
                    preview_name = user.get("성명", "홍길동")
                    preview_uuid = "샘플-UUID-1234"
        template = env.get_template(template_name)
        rendered = template.render(name=preview_name, uuid=preview_uuid)
        preview_path = os.path.abspath("preview_temp.html")
        with open(preview_path, "w", encoding="utf-8") as f:
            f.write(rendered)
        webbrowser.open("file://" + preview_path)
    except Exception as e:
        log(f"❌ 미리보기 렌더링 실패: {e}")

def show_training_status_table():
    try:
        res = requests.get(f"{SERVER_BASE}/logs/clicks")
        data = res.json()
    except Exception as e:
        log(f"❌ 감염현황 불러오기 실패: {e}")
        return
    window = ctk.CTkToplevel(app)
    window.title("감염 현황")
    window.geometry("1000x400")
    scroll = ctk.CTkScrollableFrame(window, width=960, height=360)
    scroll.pack()
    if not data:
        ctk.CTkLabel(scroll, text="데이터 없음").pack()
        return
    columns = ["name", "email", "department", "title",
               "clicked_at", "infected_at"]
    headers  = ["이름", "이메일", "부서", "직책",
                "열람 시각", "감염 시각"]
    for i, header in enumerate(headers):
        ctk.CTkLabel(scroll, text=header,
                     font=("맑은 고딕", 11, "bold"),
                     width=160, anchor="center").grid(row=0, column=i)
    for r, entry in enumerate(data, start=1):
        for c, key in enumerate(columns):
            val = entry.get(key, "") or ""
            ctk.CTkLabel(scroll, text=val,
                         font=("맑은 고딕", 10),
                         anchor="center", width=160).grid(row=r, column=c)

def start_server():
    global server_process, running
    if not running:
        try:
            server_process = subprocess.Popen([
                PYTHON_PATH, "-m", "uvicorn", "main:app",
                "--host", "0.0.0.0", "--port", str(SERVER_PORT)
            ])
            running = True
            status_label.configure(text="서버 실행 중", text_color="green")
            log("✅ 서버 시작됨")
            threading.Thread(target=update_status_loop,
                             daemon=True).start()
        except Exception as e:
            log(f"❌ 서버 실행 오류: {e}")
    else:
        log("⚠️ 서버가 이미 실행 중입니다.")

def stop_server():
    global server_process, running
    if running and server_process:
        server_process.terminate()
        server_process = None
        running = False
        status_label.configure(text="서버 중지됨", text_color="red")
        log("🛑 서버 중지됨")

def reset_training():
    try:
        res = requests.post(f"{SERVER_BASE}/start-training")
        log(f"🆕 새 훈련 시작됨: {res.json().get('message')}")
    except Exception as e:
        log(f"❌ 새 훈련 시작 실패: {e}")

def end_training():
    try:
        res = requests.post(f"{SERVER_BASE}/end-training")
        log(f"🔒 훈련 종료됨: {res.json().get('message')}")
    except Exception as e:
        log(f"❌ 훈련 종료 실패: {e}")

def export_final_report():
    try:
        res = requests.post(f"{SERVER_BASE}/export-final-report")
        log(f"📁 보고서 저장: {res.json().get('message')}")
    except Exception as e:
        log(f"❌ 보고서 저장 실패: {e}")

def update_status_loop():
    global running
    while running:
        try:
            if server_process.poll() is not None:
                running = False
                status_label.configure(text="서버 중지됨",
                                       text_color="red")
                log("🛑 서버가 종료되었습니다.")
                break
            r = requests.get(f"{SERVER_BASE}/infect-stats").json()
            count = r.get("infected_count", 0)
            total = csv_total
            rate  = round((count / total) * 100, 1) if total else 0.0
            infection_label.configure(
                text=f"🦠 감염자 수: {count}명\n전체 {total}명 | 감염률 {rate}%")
        except Exception:
            infection_label.configure(text="❌ 감염자 수: 확인 실패")
        time.sleep(2)

def select_csv():
    global csv_path, csv_total
    path = filedialog.askopenfilename(filetypes=[("CSV files","*.csv")])
    if path:
        csv_path = path
        try:
            with open(csv_path, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                csv_total = sum(1 for _ in reader)
            csv_label.configure(text=f"📄 대상자 수: 총 {csv_total}명")
            log(f"📄 CSV 로드 완료: {csv_total}명 대상")
        except Exception as e:
            log(f"❌ CSV 읽기 실패: {e}")

def send_emails():
    if not os.path.exists(csv_path):
        log("❌ CSV 파일이 존재하지 않습니다.")
        return
    try:
        tpl = selected_template.get()
        if not os.path.exists(os.path.join(template_dir, tpl)):
            log("❌ 템플릿 없음")
            return
        payload = {
            "csv_path":      csv_path,
            "template_name": tpl,
            "training_mode": training_mode,  # 2 or 3
            "server_base":   SERVER_BASE,
            "info_template_name": selected_info_template.get()
        }
        res = requests.post(f"{SERVER_BASE}/send-emails", json=payload)
        log(f"📤 메일 발송 완료: {res.json()}")
    except Exception as e:
        log(f"❌ 메일 발송 실패: {e}")

# ───────── 실행 ─────────
app.mainloop()
