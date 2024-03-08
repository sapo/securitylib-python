FROM python:3.9.5-alpine3.13
RUN  apk add --no-cache gcc libc-dev
COPY requirements.txt /
RUN pip install -r /requirements.txt 
CMD ["tail", "-f", "/dev/null"]
