FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
# /srv must mirror the api/ tree: admin_router resolves templates at
# parents[2]/templates and main.py mounts static at parents[1]/static.
COPY templates/ templates/
COPY static/ static/
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
