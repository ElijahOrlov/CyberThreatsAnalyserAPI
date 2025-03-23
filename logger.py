from datetime import datetime
import locale


class Logger:
    """
    Базовый класс логирования содержащий только дату и наименование операции
    """

    def __init__(self, operation: str = "", date: datetime = None, counter: int = 0):
        self._operation = operation
        self._date = date if date is not None else datetime.now()
        self._counter = counter

    def __repr__(self):
        return f"{self.__class__.__name__}(operation={self.operation!r}, date={self.date!r})"

    def __str__(self):
        return f"{self.date_formatted} - [{self.operation}]"

    @property
    def date(self) -> datetime:
        """
        Дата операции
        """
        return self._date

    @property
    def operation(self) -> str:
        """
        Наименование операции
        """
        return self._operation

    @operation.setter
    def operation(self, value) -> None:
        """
        Наименование операции
        """
        self._operation = value

    @property
    def date_formatted(self) -> str:
        """
        Дата операции в форматированном виде
        """
        return datetime.strftime(self.date, "%d.%m.%Y %H:%M:%S.%f")

    @property
    def counter(self) -> str:
        """
        Счетчик (инкрементация на 1 при обращении)
        """
        self._counter += 1
        return self._counter


