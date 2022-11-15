FROM python:3.8 as scanMetrics

#WORKDIR /Users/tushar.kapadi/Code/scanning
COPY . /code

RUN pip install -r /code/pip-requirements.txt

WORKDIR /code
ENV PYTHONPATH '/code/'

CMD ["python3" , "/code/scanning.py"]