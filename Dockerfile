FROM python:3.9-slim

WORKDIR /app

# ลง dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ก๊อปปี้โค้ด
COPY app.py .

# Streamlit port
EXPOSE 8501

# คำสั่งรัน
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]