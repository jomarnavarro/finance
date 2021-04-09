FROM ubuntu:latest 

RUN apt-get update -y \
	&& apt-get install -y python3-pip python3-dev \
	&& apt-get install  -y sqlite \
	&& cd /usr/local/bin \
	&& ln -s /usr/bin/python3 python \
	&& pip3 install --upgrade pip

COPY . /usr/src/app

WORKDIR /usr/src/app

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
