
1) установите зависимости
```bash
pip install -r requirements.txt
```
2) Запуск тестов
```bash
pytest
```
С выводом покрытия:
```bash
pytest --cov=main --cov-report=term-missing
```
С отчетом в HTML:
```bash
pytest --cov=main --cov-report=html
```
После запуска HTML-отчёта он будет находиться в папке htmlcov/index.html. 
Откройте файл в браузере:
```bash
xdg-open htmlcov/index.html       # Linux
open htmlcov/index.html           # macOS
start htmlcov/index.html          # Windows
```
3) Запуск FastAPI-приложения:
```bash
uvicorn main:app --reload
```
будет по адресу:
http://127.0.0.1:8000/docs
4) Запуск нагрузочного тестирования с Locust
```bash
locust -f locustfile.py
```
Откройте браузер и перейдите на:
http://localhost:8089
Введите параметры (например:
Number of users: 10
Spawn rate: 2
Нажмите "Start swarming"