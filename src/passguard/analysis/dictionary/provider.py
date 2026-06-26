from typing import Collection, Protocol
import pathlib


class DictionaryProvider(Protocol):
    def words(self) -> Collection[str]:
        ...


class SetDictionaryProvider:
    def __init__(self, words: Collection[str]) -> None:
        self._words = set(words)

    def words(self) -> Collection[str]:
        return self._words


class FileDictionaryProvider:
    def __init__(self, filepath: str | pathlib.Path) -> None:
        self._filepath = pathlib.Path(filepath)
        self._words: set[str] | None = None

    def words(self) -> Collection[str]:
        if self._words is None:
            if not self._filepath.exists():
                return set()
            with self._filepath.open("r", encoding="utf-8") as f:
                self._words = {line.strip() for line in f if line.strip()}
        return self._words


class BuiltinDictionaryProvider(FileDictionaryProvider):
    def __init__(self) -> None:
        builtin_path = pathlib.Path(__file__).parent.parent.parent / "data" / "common_passwords.txt"
        super().__init__(builtin_path)
