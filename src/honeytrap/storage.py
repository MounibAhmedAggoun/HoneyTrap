import json
from pathlib import Path

from honeytrap.events import Event


class EventStorage:
    def __init__(self, file_path: str = "data/events.jsonl"):
        self.file_path = Path(file_path)

    def save(self, event: Event) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event.to_dict()) + "\n")

    def load_all(self) -> list[dict]:
        if not self.file_path.exists():
            return []

        with self.file_path.open("r", encoding="utf-8") as file:
            return [json.loads(line) for line in file if line.strip()]