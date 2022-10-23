FROM alpine:3.14
RUN apk add --no-cache masscan & apk add --no-cache nmap apk add --no-cache python3
COPY requierements.txt .requierements.txt
RUN pip install -r requierements.txt
ADD main.py .main.py
CMD ["python", "./main.py"]