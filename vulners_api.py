"""
Часть 2. Разработка инструмента для анализа уязвимостей известного программного обеспечения с использованием базы данных Vulners
    Этап 1. Проанализируйте каждое ПО из списка на наличие уязвимостей, используя API Vulners.
    Этап 2. Для каждого ПО подготовьте отчёт, указывающий на наличие или отсутствие уязвимостей.
         Для уязвимого ПО укажите список CVE.
         Отметьте, по каким позициям доступна информация об общедоступных эксплойтах.
Исходные данные:
Формат JSON с перечнем программного обеспечения.
Список программного обеспечения, полученный для анализа:
[
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]
"""

from http import HTTPStatus
from enum import StrEnum
from requests import post, exceptions
from packaging.version import parse as version_parse, Version
from typing import Any

from settings import VULNERS_API_KEY as API_KEY
from logger import Logger


class ProgramOperationCode(StrEnum):
    """
    Коды событий операций по анализу ПО
    """
    SEARCH_VULNERABILITIES: str = "SEARCH VULNERABILITIES"
    PROGRAM_SUMMARY: str = "PROGRAM SUMMARY"
    ANALYZE_SOFTWARE: str = "ANALYZE SOFTWARE"
    OUTPUT_REPORT: str = "OUTPUT REPORT"

class BaseAPI:
    """
    Базовый класс формирования строки поиска к сервису Vulners API
    https://vulners.com/docs/api_reference/api/
    """
    _BASE_URL_PART = "https://vulners.com/api/v3"
    _SERVICE_URL_PART = ""

    def __init__(self, api_key: str):
        """
        Конструктор инициализации
        :param api_key: ключ авторизации
        """
        self._api_key = api_key

    @property
    def api_key(self) -> str:
        """
        Ключ авторизации
        """
        return self._api_key

    @property
    def url(self) -> str:
        """
        Базовая строка запроса к VirusTotal API
        """
        return f"{self._BASE_URL_PART}/{self._SERVICE_URL_PART}"

    @property
    def headers(self) -> dict[str, str]:
        """
        Заголовок запроса
        """
        return {
            "Content-Type": "application/json",  # Формат данных
            "User-Agent": "VulnerabilityScanner",  # Идентификатор клиента
            "apiKey": self.api_key  # Ключ аутентификации
        }

    @staticmethod
    def data(query: str, fields: list[str] = None, size: int = 50) -> dict[str, str]:
        """
        Search query by Lucene syntax
        """
        data = {
            "query": query,  # Поисковый запрос
            "size": size  # Максимальное количество возвращаемых результатов
        }
        if fields: data["fields"] = fields  # поля для получения из запроса
        return data

class SearchAPI(BaseAPI):
    """
    Класс формирования строки запроса (на языке Lucene) к VirusTotal для загрузки и анализа файла
    https://docs.virustotal.com/reference/file
    """
    _SERVICE_URL_PART = 'search/lucene/'

    _PROGRAM_ASSOCIATIONS = {
        "LibreOffice": ("LibreOffice","6.0.5"),
        "7zip": ("7-Zip","18.03"),
        "Adobe Reader": ("Adobe Acrobat Reader","18.009.20050"),
        "nginx": ("nginx",""),
        "Apache HTTP Server": ("apache http server",""),
        "DjVu Reader": ("DjVu",""),
        "Wireshark": ("Wireshark",""),
        "Notepad++": ("Notepad++",""),
        "Google Chrome": ("Google Chrome",""),
        "Mozilla Firefox": ("Mozilla Firefox","61.0")
    }

    def __init__(self, api_key: str):
        """
        Конструктор инициализации
        :param api_key: ключ авторизации
        """
        super().__init__(api_key)

    @classmethod
    def normalize_program(cls, program: str, version: str | Version) -> tuple[str,str]:
        """
        Нормализация наименования ПО к формату Vulners,
        Нормализация версии с учетом семантического анализа версии
        :param program: ненормализованное наименование ПО
        :param version: ненормализованная версия ПО
        :return: нормализованное наименование ПО, замененная версия ПО
        """
        norm_program = program
        if program in cls._PROGRAM_ASSOCIATIONS:
            norm_program, new_version = cls._PROGRAM_ASSOCIATIONS[program]
            if new_version: version = new_version
        return norm_program, version

    @classmethod
    def normalize_version(cls, program: str, version: str | Version) -> str | Version:
        """
        Нормализация версии с учетом семантического анализа версии
        :param program: ненормализованное наименование ПО
        :param version: ненормализованная версия ПО
        :return: нормализованная версия ПО
        """
        norm_version = version
        if program in cls._PROGRAM_ASSOCIATIONS:
            _, new_version = cls._PROGRAM_ASSOCIATIONS[program]
            if new_version: norm_version = new_version
        try:
            return version_parse(norm_version)
        except:
            return norm_version

    def search_vulnerabilities(self, program_name: str, program_version: str | Version) -> list[dict] | None:
        """
        Поиск уязвимостей в программном обеспечении (POST-запрос к API Vulners)
        :param program_name: наименование ПО
        :param program_version: версия ПО
        :return: список найденных уязвимостей из базы данных Vulners для указанного ПО (id, title, cvelist, exploit, type, description)
        """
        operation = ProgramOperationCode.SEARCH_VULNERABILITIES
        try:
            if not program_name:
                raise Exception(f"Не указано наименование ПО")
            if not program_version:
                raise Exception(f"Не указана версия ПО")

            try:
                # нормализуем наименование программы и ее версию
                norm_program, program_version = self.normalize_program(program_name, program_version)
                norm_version = self.normalize_version(program_name, program_version)

                # Формируем поисковый запрос в синтаксисе Lucene
                query = f'affectedSoftware.name:"{norm_program}" AND (affectedSoftware.version:"{norm_version}" OR affectedSoftware.version:"{program_version}")'
                fields = ["id", "title", "cvelist", "exploit", "type", "description"]
                # Формируем параметры запроса к API
                data = self.data(query, fields)

                response = post(self.url, headers=self.headers, json=data)
                response.raise_for_status()
            except exceptions.HTTPError as http_err:
                raise Exception(f"HTTP ошибка: {http_err}")
            except exceptions.RequestException as err:
                raise Exception(f"Ошибка запроса: {err}")

            if response.status_code == HTTPStatus.OK:
                search_result = response.json()
                result_data: dict[str,Any] = search_result.get("data", {})
                if search_result.get("result") == "error":
                    raise Exception(f"Ошибка в ответе: [errorCode: {result_data.get("errorCode")}] {result_data.get("error")}")
                vulnerabilities = [vulnerability.get("_source", {}) for vulnerability in result_data.get("search", [])]
                return vulnerabilities
            else:
                raise Exception(f"Ошибка выполнения поиска уязвимостей ПО: [statusCode: {response.status_code}] {response.text}")
        except Exception as ex:
            print(f"[☓] {ex}")
            return None


def generate_program_summary(vulnerability_data: dict[str, Any]) -> list[str] | None:
    """
    Генерация отчета по результатам анализа найденных уязвимостей в программном обеспечении
    :param vulnerability_data: найденные уязвимости в ПО из базы данных Vulners (program, version, cve_list, exploit_list, vulnerabilities)
    :return: Сводный отчет по программе
    """
    operation = ProgramOperationCode.PROGRAM_SUMMARY
    try:
        if not vulnerability_data:
            raise Exception(f"Не указаны уязвимости ПО")

        program = vulnerability_data.get("program", "")
        version = vulnerability_data.get("version", "")
        cve_list = vulnerability_data.get("cve_list", [])
        exploit_list = vulnerability_data.get("exploit_list", [])
        vulnerabilities = vulnerability_data.get("vulnerabilities", [])

        report = [f"## Программное обеспечение: {program} {version} ##"]
        counter = 1
        if vulnerabilities and len(vulnerabilities) > 0:
            report.append(f"{counter}. Уязвимости: детектировано [{len(vulnerabilities)}]")
            counter += 1
            if cve_list and len(cve_list) > 0:
                report.append(f"{counter}. CVE: обнаружено [{len(cve_list)}]: {', '.join(cve_list)}")
            else:
                report.append(f"{counter}. CVE НЕ ОБНАРУЖЕНО!")
            counter += 1
            if exploit_list and len(exploit_list) > 0:
                report.append(f"{counter}. Эксплойты: найдено [{len(exploit_list)}]: {', '.join(cve_list)}")
            else:
                report.append(f"{counter}. Эксплойты НЕ НАЙДЕНЫ!")
            counter += 1
            report.append(f"{counter}. Детализация:")
            for pos, vulnerability in enumerate(vulnerabilities):
                num = pos + 1
                title = vulnerability.get("title")
                report.append(f" {counter}.{num}. {title}")

                cve = vulnerability.get("cvelist", [])
                report.append(f"   {u'\u25AA'} CVE уязвимости: {(', '.join(cve) if (cve and len(cve) > 0) else 'НЕ ОБНАРУЖЕНЫ!')}")

                exploit_available = any(vulnerability.get("exploit", {}).values())
                report.append(f"   {u'\u25AA'} Эксплойт: {('☑ доступен' if exploit_available else '☒ отсутствует')}")

                description = vulnerability.get("description").replace('\n'," ")
                report.append(f"   {u'\u25AA'} Описание: {description[:150]}{'...' if len(description) > 150 else ''}")
        else:
            report.append(f"{counter}. Уязвимости НЕ НАЙДЕНЫ!")
        report.append("-" * 50)

        return report
    except Exception as ex:
        print(f"[☓] {ex}")
        return None

def analyze_software(api_key: str, software_list: list[dict[str, str]], logger: Logger = None) -> list[dict[str,Any]] | None:
    """
    Сбор данных по результатам анализа найденных уязвимостей в программном обеспечении
    {'analyses_id', str} - идентификатор анализа архива

    :param api_key: ключ авторизации
    :param software_list: список ПО для анализа на уязвимости
    :param logger: логгер операций
    :return: справочник с результатом анализа (program, version, summary)
    """
    if not api_key or not software_list: return None

    try:
        print("Поиск уязвимостей в программном обеспечении из базы данных Vulners")
        print("-" * 31 + "\n")

        # логер
        if not logger: logger = Logger(ProgramOperationCode.ANALYZE_SOFTWARE)
        else: logger.operation = ProgramOperationCode.ANALYZE_SOFTWARE

        # итоговый список отчетов по ПО
        software_report: list[dict[str,Any]] = []

        # формируем API поиска уязвимостей
        search_api = SearchAPI(api_key)
        for software in software_list:
            program = software["Program"]
            version = software["Version"]
            print(f"{logger.counter}. Анализ [{program} {version}]")

            # ищем уязвимости в программном обеспечении
            vulnerabilities = search_api.search_vulnerabilities(program, version)
            if vulnerabilities and len(vulnerabilities) > 0:
                print(f"---> Сформирован список общедоступных уязвимостей (vulnerabilities: {len(vulnerabilities)})")
            else:
                print(f"---> Уязвимости НЕ НАЙДЕНЫ!!!")

            # формируем общий список CVE по всем уязвимостям
            cve_list = []
            for vulnerability in vulnerabilities:
                cve_list.extend(vulnerability.get("cvelist", []))
            if cve_list and len(cve_list) > 0:
                print(f"---> Сформирован список CVE (cve_list: {len(cve_list)})")

            # формируем общий список эксплойтов по всем уязвимостям
            exploit_list = []
            for vulnerability in vulnerabilities:
                exploit_list.extend(vulnerability.get("exploit", {}).values())
            if exploit_list and len(exploit_list) > 0:
                print(f"---> Сформирован список эксплойтов (exploit_list: {len(exploit_list)})")

            # формируем отчет по результатам анализа найденных уязвимостей в программном обеспечении
            vulnerability_data = {
                "program": program,
                "version": version,
                "cve_list": cve_list,
                "exploit_list": exploit_list,
                "vulnerabilities": vulnerabilities
            }
            program_summary = generate_program_summary(vulnerability_data)
            if program_summary:
                print(f"---> Сформирован отчет по найденным уязвимостям (program_summary)")
                software_report.append({
                    "program": program,
                    "version": version,
                    "summary": program_summary
                })

        return software_report
    except Exception as ex:
        print(f"[☓] Ошибка сбора данных по результатам анализа найденных уязвимостей в программном обеспечении: {ex}")
        return None

def generate_report(software_report: list[dict[str,Any]], output_filename: str = "vulners_report.txt", logger: Logger = None) -> None:
    """
    Генерация суммарного отчета по результатам анализа списка ПО на уязвимости
    :param software_report: отчет по результатам анализа найденных уязвимостей в программном обеспечении
    :param output_filename: путь для сохранения файла с отчетом
    :param logger: логгер
    """
    if not software_report or not output_filename: return

    try:
        # логер
        if not logger: logger = Logger(ProgramOperationCode.OUTPUT_REPORT)
        else: logger.operation = ProgramOperationCode.OUTPUT_REPORT

        with open(output_filename, "w", encoding="utf-8") as file:
            file.write("Отчет анализа программного обеспечения на наличие уязвимостей\n")
            file.write("-" * 61 + "\n\n")

            for report in software_report:
                summary: list[str] = report["summary"]
                file.write(f"{'\n'.join(summary)}\n\n")

            print(f"{logger.counter}. Сформирован суммарный отчет по результатам анализа списка ПО на уязвимости: {output_filename}")
    except Exception as ex:
        print(f"[☓] Ошибка формирования отчета по результатам анализа списка ПО: {ex}")
        return None


if __name__ == "__main__":
    SOFTWARE = [
        {"Program": "LibreOffice", "Version": "6.0.7"},
        {"Program": "7zip", "Version": "18.05"},
        {"Program": "Adobe Reader", "Version": "2018.011.20035"},
        {"Program": "nginx", "Version": "1.14.0"},
        {"Program": "Apache HTTP Server", "Version": "2.4.29"},
        {"Program": "DjVu Reader", "Version": "2.0.0.27"},
        {"Program": "Wireshark", "Version": "2.6.1"},
        {"Program": "Notepad++", "Version": "7.5.6"},
        {"Program": "Google Chrome", "Version": "68.0.3440.106"},
        {"Program": "Mozilla Firefox", "Version": "61.0.1"}
    ]

    try:
        logger = Logger()
        software_report = analyze_software(API_KEY, SOFTWARE, logger)
        if software_report:
            generate_report(software_report, "vulners_software_report.txt", logger)
    except KeyboardInterrupt:
        print("\nПрервано пользователем...")
    except Exception as ex:
        print(ex)