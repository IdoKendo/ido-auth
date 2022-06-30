class UnverifiedException(Exception):
    def __init__(self, err: str):
        self.err = err
