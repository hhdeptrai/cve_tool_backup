import vertexai
from vertexai.generative_models import GenerativeModel
vertexai.init(project="project-49966148-9e92-4a21-949", location="us-central1")
model = GenerativeModel("gemini-2.5-pro")
chat = model.start_chat()
print("Sending message...")
try:
    response = chat.send_message("Hello")
    print(response.text)
except Exception as e:
    print(f"Error: {e}")
