FROM python:3.12
WORKDIR .
COPY . .
RUN pip install -r app/requirements.txt
RUN pip install uvicorn
RUN ["uvicorn", "app/main:app"]
