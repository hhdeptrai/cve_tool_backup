from google import genai
from google.genai import types
import os

os.environ.pop('HTTP_PROXY', None)
os.environ.pop('HTTPS_PROXY', None)

api_key = "AIzaSyCcXLH95VXeXsLLd2WLOkHuMOFJi8eKAlk"
model_name = "gemini-3-flash"

try:
    client = genai.Client(api_key=api_key)
    print("Testing Google Search capability...")
    
    # We ask a question that requires live search to test if grounded search works
    response = client.models.generate_content(
        model=model_name,
        contents="Tìm cho tôi tin tức mới nhất về vụ tấn công CVE-2024-9148",
        config=types.GenerateContentConfig(
            tools=[{"google_search": {}}],
        )
    )
    print("✅ Search Response:\n")
    print(response.text)

except Exception as e:
    print(f"❌ Error: {str(e)}")
