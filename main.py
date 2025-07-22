import os
import csv
import uuid
import logging
from datetime import datetime
from uuid import UUID
from dotenv import load_dotenv
import sys

import uvicorn
from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import aiosmtplib
from jinja2 import Environment, FileSystemLoader
from psycopg2.extras import RealDictCursor
from email.message import EmailMessage

from db import get_connection

# ──────────────────────────────────────────────────────────
# 로깅 설정
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s"
)
# 환경 변수 로드
load_dotenv()

# FastAPI 앱 초기화
app = FastAPI()

# ───────── 경로 헬퍼 ─────────
def resource_path(relative: str) -> str:
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative)

app.mount("/files", StaticFiles(directory=resource_path("files")), name="files")

# 템플릿 설정
templates = Jinja2Templates(directory=resource_path("templates"))
env = Environment(loader=FileSystemLoader(resource_path("templates")))

# 현재 훈련 테이블 관리
CURRENT_TABLE_FILE = "current_training_table.txt"
def get_current_table() -> str | None:
    if os.path.exists(CURRENT_TABLE_FILE):
        with open(CURRENT_TABLE_FILE) as f:
            return f.read().strip()
    return None

def set_current_table(table_name: str):
    with open(CURRENT_TABLE_FILE, "w") as f:
        f.write(table_name)

def is_locked(table: str) -> bool:
    return table.endswith("_locked")

async def record_click(id: UUID, request: Request):
    table = get_current_table()
    if not table or is_locked(table):
        return
    now    = datetime.now()
    ip     = request.client.host
    ua     = request.headers.get("user-agent", "")
    ref    = request.headers.get("referer", "")
    lang   = request.headers.get("accept-language", "")
    try:
        conn = get_connection()
        cur  = conn.cursor()
        cur.execute(
            f"""
            UPDATE {table}
               SET clicked_at      = %s,
                   ip_address      = %s,
                   user_agent      = %s,
                   referer         = %s,
                   accept_language = %s
             WHERE id = %s
               AND clicked_at IS NULL
            """,
            (now, ip, ua, ref, lang, str(id)),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logging.error(f"record_click error: {e}")


async def record_infection(id: UUID, request: Request):
    table = get_current_table()
    if not table or is_locked(table):
        return False
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            f"""
            INSERT INTO {table}
                (id, ip_address, user_agent, referer, accept_language, clicked_at, infected_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE
              SET
                infected_at      = EXCLUDED.infected_at,
                clicked_at       = COALESCE(EXCLUDED.clicked_at, {table}.clicked_at),
                ip_address       = EXCLUDED.ip_address,
                user_agent       = EXCLUDED.user_agent,
                referer          = EXCLUDED.referer,
                accept_language  = EXCLUDED.accept_language
            """,
            (
                str(id),
                request.client.host,
                request.headers.get("user-agent", ""),
                request.headers.get("referer", ""),
                request.headers.get("accept-language", ""),
                datetime.now(),
                datetime.now(),
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logging.error(f"record_infection error: {e}")
        return False

# JSON 바디 모델
training_mode = 2  # 2단계 기본값

class SendEmailRequest(BaseModel):
    csv_path: str
    template_name: str
    training_mode: int = 2
    server_base: str | None = None

# 1) 훈련 시작
@app.post("/start-training")
async def start_training():
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    table = f"phishing_click_logs_{now}"
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id UUID PRIMARY KEY,
                employee_no TEXT,
                name TEXT,
                email TEXT,
                department TEXT,
                title TEXT,
                ip_address TEXT,
                user_agent TEXT,
                referer TEXT,
                accept_language TEXT,
                clicked_at TIMESTAMP,
                infected_at TIMESTAMP
            )
        """)
        conn.commit()
        cur.close()
        conn.close()
        set_current_table(table)
        return {"message": f"새 훈련 시작됨: {table}"}
    except Exception as e:
        logging.error(f"start_training error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# 2) 훈련 종료
@app.post("/end-training")
async def end_training():
    table = get_current_table()
    if not table:
        return JSONResponse(status_code=400, content={"error": "진행 중인 훈련 없음"})
    locked_table = f"{table}_locked"
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(f"ALTER TABLE {table} RENAME TO {locked_table};")
        conn.commit()
        cur.close()
        conn.close()
        set_current_table(locked_table)
        return {"message": f"훈련 종료 및 테이블 잠금: {locked_table}"}
    except Exception as e:
        logging.error(f"end_training error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# 3) 최종보고서 저장
@app.post("/export-final-report")
async def export_final_report():
    table = get_current_table()
    if not table:
        return JSONResponse(status_code=400, content={"error": "훈련 테이블이 설정되지 않음"})

    try:
        # ① 추출할 컬럼 명시
        cols = [
            "id",
            "employee_no",
            "name",
            "email",
            "department",
            "title",
            "ip_address",
            "user_agent",
            "referer",
            "accept_language",
            "clicked_at",
            "infected_at"
        ]
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"SELECT {', '.join(cols)} FROM {table}")
        records = cur.fetchall()
        cur.close()
        conn.close()

        # ② 통계 계산
        total = len(records)
        viewed = sum(1 for r in records if r.get("clicked_at"))
        infected = sum(1 for r in records if r.get("infected_at"))
        infection_rate = round(infected / total * 100, 2) if total else 0

        # ③ 시간 포맷
        now = datetime.now()
        now_str = now.strftime("%Y%m%d_%H%M")
        display_ts = now.strftime("%Y-%m-%d %H:%M:%S")

        # ④ CSV 쓰기
        os.makedirs("logs", exist_ok=True)
        filename = f"logs/final_report_{now_str}.csv"
        with open(filename, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)

            # 타이틀 행
            writer.writerow(
                ["", ""] +
                [f"({display_ts}) 훈련결과"] +
                [""] * (len(cols) - 2)
            )
            # 통계 행
            writer.writerow([
                "총 대상자 수", total,
                "총 열람수", viewed,
                "총 감염수", infected,
                "감염률", f"{infection_rate}%"
            ])
            writer.writerow([])

            # 상세 헤더 (한글 매핑)
            header_map = {
                "id": "ID",
                "employee_no": "사번",
                "name": "이름",
                "email": "이메일",
                "department": "부서",
                "title": "직책",
                "ip_address": "IP",
                "user_agent": "User-Agent",
                "referer": "Referer",
                "accept_language": "Accept-Language",
                "clicked_at": "열람 시각",
                "infected_at": "감염 시각",
            }
            writer.writerow([header_map[c] for c in cols] + ["상태"])

            # 데이터 행
            for r in records:
                status = (
                    "감염" if r.get("infected_at")
                    else ("열람" if r.get("clicked_at") else "미열람")
                )
                row = [r.get(c, "") for c in cols] + [status]
                writer.writerow(row)

        return {"message": f"보고서 저장 완료: {filename}"}

    except Exception as e:
        logging.error(f"export_final_report error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# 4) 클릭 로그 조회
@app.get("/logs/clicks")
async def get_click_logs():
    table = get_current_table()
    if not table or is_locked(table):
        return []
    try:
        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"SELECT * FROM {table} ORDER BY clicked_at DESC NULLS LAST")
        logs = cur.fetchall()
        cur.close()
        conn.close()
        return logs
    except Exception as e:
        logging.error(f"get_click_logs error: {e}")
        return JSONResponse(status_code=500, content={"error": "조회 실패", "detail": str(e)})

# 5) 메일 발송 (JSON 바디 방식)
@app.post("/send-emails")
async def send_emails(payload: SendEmailRequest = Body(...)):
    global training_mode
    training_mode = payload.training_mode
    table = get_current_table()
    if not table or is_locked(table):
        return JSONResponse(status_code=400, content={"error": "활성화된 훈련 없음 또는 이미 종료됨"})
    try:
        # CSV 파일 열기
        with open(payload.csv_path, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        total = len(rows)
        success_list, fail_list = [], []
        template = env.get_template(payload.template_name)

        for row in rows:
            unique_id = str(uuid.uuid4())
            try:
                # DB 삽입
                conn = get_connection()
                cur = conn.cursor()
                cur.execute(
                    f"INSERT INTO {table} (id, employee_no, name, email, department, title) "
                    "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                    (
                        unique_id,
                        row.get("사번", ""),
                        row.get("성명", ""),
                        row.get("이메일", ""),
                        row.get("부서", ""),
                        row.get("직책", "")
                    )
                )
                conn.commit()
                cur.close()
                conn.close()

                # 메일 전송
                html = template.render(
                    name=row.get("성명", ""),
                    uuid=unique_id,
                    training_mode=training_mode,
                    server_base=payload.server_base,
                )
                msg = EmailMessage()
                msg["Subject"] = "[중요] 의심스러운 로그인 시도가 차단됨"
                msg["From"] = os.getenv("SMTP_FROM")
                msg["To"] = row.get("이메일", "")
                msg.set_content("HTML 미지원 메일입니다.")
                msg.add_alternative(html, subtype="html")

                await aiosmtplib.send(
                    msg,
                    hostname=os.getenv("SMTP_HOST"),
                    port=int(os.getenv("SMTP_PORT", "25")),
                    username=os.getenv("SMTP_USER"),
                    password=os.getenv("SMTP_PASSWORD"),
                    start_tls=False
                )
                row["수신"] = "성공"
                success_list.append(row)

            except Exception as e:
                logging.error(f"SMTP send error for {row.get('이메일')}: {e}")
                row["수신"] = "실패"
                row["오류메시지"] = str(e)
                fail_list.append(row)

        # 결과 CSV 저장
        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = f"수신기록_{now_str}.csv"
        original_keys = ["사번", "성명", "이메일", "부서", "직책"]
        fieldnames = original_keys + ["수신", "오류메시지"]
        with open(out_file, "w", newline="", encoding="utf-8-sig") as wf:
            writer = csv.DictWriter(wf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(success_list + fail_list)

        return {"total": total, "sent": len(success_list), "fail": len(fail_list), "saved_csv": out_file}

    except Exception as e:
        logging.error(f"send_emails error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# 6) 피싱 감염 기록
@app.get("/infect")
async def infect(id: UUID, request: Request):
    await record_infection(id, request)
    return templates.TemplateResponse("감염페이지.html", {"request": request})


# 7) 클릭 추적
@app.get("/track")
async def track_click(id: UUID, request: Request):
    table = get_current_table()
    if not table or is_locked(table):
        return HTMLResponse(status_code=204)

    await record_click(id, request)

    # 투명 픽셀 응답
    return RedirectResponse(url="/files/1x1.png", status_code=204)

# 7-1) 개인정보 입력 화면 (3단계용)
@app.get("/view-info")
async def view_info(id: UUID, request: Request):
    await record_click(id, request)
    return templates.TemplateResponse("개인정보입력페이지.html", {"request": request, "id": id})

# 7-2) 개인정보 전송 후 감염 처리
@app.post("/submit-info")
async def submit_info(id: UUID, request: Request):
    await record_infection(id, request)
    return templates.TemplateResponse("감염페이지.html", {"request": request})

# 8) 감염 통계 제공
@app.get("/infect-stats")
async def get_infect_stats():
    table = get_current_table()
    if not table or is_locked(table):
        return {"infected_count": 0}
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE infected_at IS NOT NULL")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {"infected_count": count}
    except Exception as e:
        logging.error(f"get_infect_stats error: {e}")
        return {"infected_count": 0, "error": str(e)}

# 앱 실행
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="warning")
