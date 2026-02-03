FROM python:3.9-slim

WORKDIR /app

# เพิ่ม graphviz เพื่อวาดแผนผัง Tree
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    python3-dev \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--theme.base=dark"]