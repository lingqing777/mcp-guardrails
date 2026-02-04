FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY waf2_proxy.py .

EXPOSE 8081

CMD ["python", "waf2_proxy.py"]
