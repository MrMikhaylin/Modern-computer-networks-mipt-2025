FROM docker.io/rerand0m/cn-alpine:latest

WORKDIR /acme

COPY . .

RUN apk add --no-cache py3-pip py3-cryptography

EXPOSE 80

CMD ["python", "app.py"]