import vertexai
from vertexai.generative_models import GenerativeModel

# Thay bằng Project ID thật của ông (lấy trên console.cloud.google.com)
PROJECT_ID = "project-49966148-9e92-4a21-949" 

vertexai.init(project=PROJECT_ID, location="us-central1")

# Thử luôn bản 3.1 cho máu, không được thì hạ xuống 1.5-pro
model = GenerativeModel("gemini-2.5-pro") 

try:
    print("--- Đang kết nối Gemini qua Ubuntu ---")
    response = model.generate_content("Chào Gemini, bạn là phiên bản mấy?")
    print("\n[KẾT QUẢ]:")
    print(response.text)
    print("\n✅ NGON! Đã chạy thành công trên Ubuntu bằng $300 Free Trial.")
except Exception as e:
    print(f"❌ Lỗi: {e}")
