from locust import HttpUser, task, between
import random
import string
import json


class TaskAPIUser(HttpUser):
    wait_time = between(1, 3)
    host = "http://0.0.0.0:8000"
    token = None
    username = None

    def on_start(self):
        self.username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        password = "password123"
        self.client.post(
            "/register/",
            params={"username": self.username, "password": password}
        )

        response = self.client.post(
            "/token",
            data={"username": self.username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        result = response.json()
        self.token = result.get("access_token")
        if not self.token:
            self.environment.runner.quit()

    @task(3)
    def create_task(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        task_title = f"Task {''.join(random.choices(string.ascii_lowercase, k=5))}"
        task_description = f"Description {''.join(random.choices(string.ascii_lowercase, k=15))}"
        task_priority = random.randint(1, 5)

        self.client.post(
            "/tasks/",
            headers=headers,
            params={
                "title": task_title,
                "description": task_description,
                "priority": task_priority
            }
        )

    @task(2)
    def get_tasks(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        self.client.get("/tasks/", headers=headers)

    @task(1)
    def get_sorted_tasks(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        sort_options = ["title", "status", "created_at"]
        sort_by = random.choice(sort_options)
        self.client.get(f"/tasks/?sort_by={sort_by}", headers=headers)

    @task(1)
    def search_tasks(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        search_term = ''.join(random.choices(string.ascii_lowercase, k=3))
        self.client.get(f"/tasks/?search={search_term}", headers=headers)


class TaskAPIWithCacheUser(TaskAPIUser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cached_searches = ["important", "urgent", "meeting", "review"]

    @task(3)
    def get_cached_search(self):
        if not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        search_term = random.choice(self.cached_searches)
        self.client.get(f"/tasks/?search={search_term}", headers=headers)