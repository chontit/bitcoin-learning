FROM python:3.9-slim

WORKDIR /app

# [NEW] ติดตั้งเครื่องมือสำหรับ Build (แก้ปัญหา pip install error)
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]