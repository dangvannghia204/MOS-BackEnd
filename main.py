from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, db
import hmac
import hashlib
import os
import json

app = FastAPI()

# --- 1. LẤY BIẾN MÔI TRƯỜNG BẢO MẬT TỪ HOST (RENDER) ---
# Trên máy ảo của Render, bạn sẽ cấu hình các biến này trong mục Environment
ENCRYPT_KEY = os.environ.get("ENCRYPT_KEY", "fallback_key_neu_quen_cau_hinh")
SALT = os.environ.get("SALT", "fallback_salt")
FIREBASE_URL = os.environ.get("FIREBASE_URL")

# --- 2. KHỞI TẠO FIREBASE ADMIN ---
# Khóa quản trị Firebase (Service Account) chứa thông tin nhạy cảm.
# Thay vì lưu thành file json trên Github, ta lưu nội dung chuỗi JSON đó vào biến môi trường.
firebase_cert_json = os.environ.get("FIREBASE_CERT_JSON")

if not firebase_admin._apps:
    try:
        cert_dict = json.loads(firebase_cert_json)
        cred = credentials.Certificate(cert_dict)
        firebase_admin.initialize_app(cred, {
            'databaseURL': FIREBASE_URL
        })
    except Exception as e:
        print(f"Lỗi khởi tạo Firebase: {e}")

# --- 3. ĐỊNH NGHĨA CẤU TRÚC GÓI TIN NHẬN TỪ CLIENT ---
class SubmissionPayload(BaseModel):
    user: str
    score: int
    max_score: int
    signature: str
    usage_id: str
    code_hash: str
    user: str
    timestamp: int
    
# --- 4. HÀM TỰ TÍNH TOÁN LẠI CHỮ KÝ (HMAC) ---
def verify_signature(user: str, score: int, max_score: int, client_sig: str) -> bool:
    # Gom dữ liệu theo ĐÚNG THỨ TỰ mà file .exe đã gom (ví dụ dưới đây là 1 chuẩn chung)
    # Bạn phải đảm bảo quy tắc ghép chuỗi ở Server giống hệt ở Client
    raw_data = f"{user}|{score}|{max_score}|{SALT}"
    
    # Băm HMAC bằng ENCRYPT_KEY
    expected_sig = hmac.new(
        key=ENCRYPT_KEY.encode('utf-8'),
        msg=raw_data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # So sánh an toàn chống tấn công timing attack
    return hmac.compare_digest(expected_sig, client_sig)

# --- 5. ĐIỂM TIẾP NHẬN BÀI THI (API ENDPOINT) ---
@app.post("/api/submit")
async def submit_exam(payload: SubmissionPayload):
    # Bước 1: Xác thực chữ ký có phải do phần mềm .exe thật gửi không
    is_valid = verify_signature(
        payload.user, 
        payload.score, 
        payload.max_score, 
        payload.signature
    )
    
    if not is_valid:
        # Nếu chữ ký sai (do dùng Postman fake điểm), trả về lỗi 403 ngay
        raise HTTPException(status_code=403, detail="Phát hiện gian lận: Chữ ký không hợp lệ!")
    
    # Bước 2: Chữ ký chuẩn, tiến hành dùng quyền Admin đẩy vào Firebase
    try:
        # Gọi thẳng vào bảng submissions (Ghi đè hoặc tạo mới tuỳ logic)
        ref = db.reference(f"submissions/{payload.user}")
        ref.set({
            "score": payload.score,
            "max_score": payload.max_score,
            # Bỏ signature đi vì lên server là xong rồi, không cần lưu vào db
            "timestamp": dict(firebase_admin.db.ServerValue.TIMESTAMP) 
        })
        return {"status": "success", "message": "Nộp bài và lưu điểm an toàn thành công!"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi Server khi ghi Database: {str(e)}")

@app.post("/api/use-code")
async def record_code_usage(payload: CodeUsagePayload):
    try:
        # Máy chủ dùng quyền Admin ghi thẳng vào thư mục code_usages
        ref = db.reference(f"code_usages/{payload.usage_id}")
        ref.set({
            "code_hash": payload.code_hash,
            "user": payload.user,
            "timestamp": payload.timestamp
        })
        return {"status": "success"}
    except Exception as e:
        # In lỗi ngầm ra console của máy chủ để dễ debug
        print(f"Lỗi ghi code_usage: {e}") 
        return {"status": "error"}
    
# Khởi động app nội bộ (Render sẽ dùng uvicorn để chạy tự động)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)