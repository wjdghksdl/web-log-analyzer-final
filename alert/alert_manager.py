import json


def save_alerts(data, file_path="data/alerts.json"):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def load_alerts(file_path="data/alerts.json"):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)
