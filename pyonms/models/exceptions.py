# pyonms.models.exceptions.py

from typing import List


class StringLengthException(Exception):
    def __init__(self, length: int, value: str = None):
        self.max_length = length
        self.value = value
        self.message = f"String length must be under {self.max_length} characters."
        if self.value:
            self.message += f" Value was '{self.value}'."
        super().__init__(self.message)


class DuplicateEntityException(Exception):
    def __init__(self, name: str, model):
        self.name = name
        self.model = model
        self.message = f"A {type(self.model)} object named {self.name} already exists."
        super().__init__(self.message)


class InvalidValueException(Exception):
    def __init__(self, name: str, value: str, valid: List[str] = None):
        self.name = name
        self.value = value
        self.valid = valid
        self.message = f"{self.name} received an invalid value of {self.value}."
        if valid:
            self.message += f" Valid options are {self.valid}."
        super().__init__(self.message)
