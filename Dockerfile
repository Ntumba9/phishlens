FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY phishlens ./phishlens

# Cases live in a mounted volume so they survive the container. The store
# has no authentication: publish the port only on localhost unless you
# mean to share every stored email.
ENV PHISHLENS_DB=/data/cases.db
VOLUME /data
EXPOSE 8000
CMD ["uvicorn", "phishlens.api:app", "--host", "0.0.0.0", "--port", "8000"]
