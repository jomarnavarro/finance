FROM python:3.8.11-alpine3.14

RUN apk add sqlite

COPY . /usr/src/app

WORKDIR /usr/src/app

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
