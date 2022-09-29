# pyonms.models.exceptions.py


class StringLengthException(Exception):
    def __init__(self, length: int):
        self.max_length = length
        self.message = f"String length must be under {self.max_length} characters."
        super().__init__(self.message)


class DuplicateEntityException(Exception):
    def __init__(self, name: str, model):
        self.name = name
        self.model = model
        self.message = f"A {type(self.model)} object named {self.name} already exists."
        super().__init__(self.message)
