"""
Часть 1. Разработка инструмента для анализа киберугроз с использованием VirusTotal API
Этапы выполнения задания (часть 1)
    Этап 1. Распаковка архива.
    - Используя Python, распакуйте предоставленный архив и извлеките файлы.
    Этап 2. Анализ файлов через VirusTotal API.
    - Отправьте файлы на анализ, используя ваш персональный API-ключ VirusTotal.
    Этап 3. Обработка результатов сканирования.
    - Проанализируйте ответы от VirusTotal, собирая данные о детектировании угроз антивирусами.
    Этап 4. Подготовка отчёта. Составьте отчёт со статистикой результатов сканирования. Включите в отчёт код скрипта и результат его вывода в виде скриншота (JPG, PNG).
    - Приведите список антивирусов, которые обнаружили угрозы, в формате: Detected, ALYac, Kaspersky.
    - Сравните результаты с заданным списком антивирусов и песочниц. Укажите, какие из указанных антивирусов (Fortinet, McAfee, Yandex, Sophos) детектировали угрозу, а какие нет.
    Дополнительные задачи
    ● Если доступен отчёт VirusTotal Sandbox о поведении вредоноса, проанализируйте его и включите в свой отчёт ключевые моменты из него.
    ● Выведите список доменов и IP-адресов, с которыми вредонос общается, (для блокировки) и описание поведения (Behavior) от VirusTotal Sandbox, если оно доступно.
"""
import time
from enum import StrEnum
from http import HTTPStatus
from typing import Any
from requests import post, get, exceptions
import zipfile

from settings import VIRUSTOTAL_API_KEY as API_KEY
from logger import Logger


class FileOperationCode(StrEnum):
    """
    Коды событий операций по анализу файла
    """
    FILE_UPLOAD: str = "FILE UPLOAD"
    FILE_RESCAN: str = "FILE RESCAN"
    ANALYSE_REPORT: str = "ANALYSE REPORT"
    BEHAVIOURS_REPORT: str = "BEHAVIOURS REPORT"
    ANALYSE_FILE: str = "ANALYSE FILE"
    OUTPUT_REPORT: str = "OUTPUT REPORT"

class BaseAPI:
    """
    Базовый класс формирования строки запроса к сервису VirusTotal API
    https://virustotal-api-3-manual-rus.readthedocs.io/en/latest/endpoints.html
    """
    _BASE_URL_PART = "https://www.virustotal.com/api/v3"
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
        Заголовок запроса с уникальным ключом авторизации
        """
        return {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

class FilesAPI(BaseAPI):
    """
    Класс формирования строки запроса к VirusTotal для загрузки и анализа файла
    https://docs.virustotal.com/reference/file
    """
    _SERVICE_URL_PART = 'files'

    def __init__(self, api_key: str, archive_filename: str, archive_password: str = None):
        """
        Конструктор инициализации
        :param api_key: ключ авторизации
        :param archive_filename: наименование загружаемого архива в формате zip
        :param archive_password: пароль к защищенному zip архиву при наличии
        """
        super().__init__(api_key)
        self._archive_filename: str = archive_filename
        self._archive_password: str = archive_password

    @property
    def archive_filename(self) -> str | None:
        """
        Наименование загружаемого архива в формате zip
        """
        return self._archive_filename

    @property
    def archive_password(self) -> str | None:
        """
        Пароль к защищенному zip архиву
        """
        return self._archive_password


    def upload_file(self) -> str | None:
        """
        Загрузить и отправить на анализ файл (Upload and analyse a file)
        [post] - https://www.virustotal.com/api/v3/files
        :return: ID анализа файла
        """
        operation = FileOperationCode.FILE_UPLOAD
        try:
            if not self.archive_filename:
                raise Exception(f"Не задан архив для анализа")
            if not zipfile.is_zipfile(self.archive_filename):
                raise Exception("Uploading archive is not a ZIP file")

            payload = {"password": self.archive_password} if self.archive_password else None
            try:
                with open(self.archive_filename, "rb") as file:
                    files = {"file": (self.archive_filename, file, "application/x-zip-compressed")}
                    #print(f"Загрузка архива {self.archive_filename} для анализа.  Ожидайте...")
                    response = post(self.url, headers=self.headers, files=files, data=payload)
                    response.raise_for_status()
            except exceptions.HTTPError as http_err:
                raise Exception(f"HTTP ошибка: {http_err}")
            except exceptions.RequestException as err:
                raise Exception(f"Ошибка запроса: {err}")

            if response.status_code == HTTPStatus.OK:
                file_analyses = response.json()
                analyses_id = file_analyses["data"]["id"]
                return analyses_id
            else:
                raise Exception(f"Ошибка загрузки архива: [statusCode: {response.status_code}] {response.text}")
        except Exception as ex:
            print(f"[-] {ex}")
            return None

    def rescan_file(self, analyses_id: str) -> str | None:
        """
        Повторно отправить файл на анализ без загрузки содержимого (Request a file rescan (re-analyze)  already in VirusTotal)
        [post] - https://www.virustotal.com/api/v3/files/{id}/analyse
        :param analyses_id: ID анализа файла
        :return: ID анализа файла
        """
        operation = FileOperationCode.FILE_RESCAN
        try:
            if not analyses_id:
                raise Exception(f"Отсутствует идентификатор анализа файла (AnalysesID)")

            url = f"{self.url}/{analyses_id}/analyse"
            try:
                response = post(url, headers=self.headers)
                response.raise_for_status()
            except exceptions.HTTPError as http_err:
                raise Exception(f"HTTP ошибка: {http_err}")
            except exceptions.RequestException as err:
                raise Exception(f"Ошибка запроса: {err}")

            if response.status_code == HTTPStatus.OK:
                file_analyses = response.json()
                analyses_id = file_analyses["data"]["id"]
                return analyses_id
            else:
                raise Exception(f"Ошибка анализа архива: [statusCode: {response.status_code}] {response.text}")
        except Exception as ex:
            print(f"[-] {ex}")
            return None

    def behaviours_report(self, file_id: str) -> Any | None:
        """
        Получить отчет по поведенческой информации о файле из каждой изолированной среды
        [get] - https://www.virustotal.com/api/v3/files/{id}/behaviours
        :param file_id: ID файла SHA-256
        :return: отчет о поведении
        """
        operation = FileOperationCode.BEHAVIOURS_REPORT
        try:
            if not file_id:
                raise Exception(f"Отсутствует идентификатор файла SHA-256 (FileID)")

            url = f"{self.url}/{file_id}/behaviours"
            while True:
                try:
                    response = get(url, headers=self.headers)
                    response.raise_for_status()
                except exceptions.HTTPError as http_err:
                    raise Exception(f"HTTP ошибка: {http_err}")
                except exceptions.RequestException as err:
                    raise Exception(f"Ошибка запроса: {err}")

                if response.status_code == HTTPStatus.OK:
                    behaviours_report = response.json()
                    return behaviours_report["data"]
                else:
                    raise Exception(f"Ошибка формирования отчета о поведении: [statusCode: {response.status_code}] {response.text}")
        except Exception as ex:
            print(f"[-] {ex}")
            return None

class AnalysesAPI(BaseAPI):
    """
    Класс формирования строки запроса к VirusTotal для получения отчета по сканированию файла
    https://docs.virustotal.com/reference/analysis
    """
    _SERVICE_URL_PART = 'analyses'

    def __init__(self, api_key: str, analyses_id: str):
        """
        Конструктор инициализации
        :param api_key: ключ авторизации
        :param analyses_id: идентификатор анализа архива
        """
        super().__init__(api_key)
        self._analyses_id: str = analyses_id

    @property
    def analyses_id(self) -> str:
        """
        Идентификатор анализа архива
        """
        return self._analyses_id

    def analyse_report(self) -> tuple[str, Any] | None:
        """
        Получить отчет по анализу файла (Get a URL / file analyses)
        [get] - https://www.virustotal.com/api/v3/analyses/{id}
        :return: (ID файла, отчет)
        """
        operation = FileOperationCode.ANALYSE_REPORT
        try:
            if not self.analyses_id:
                raise Exception(f"Отсутствует идентификатор анализа файла (AnalysesID)")

            url = f"{self.url}/{self.analyses_id}"
            while True:
                try:
                    response = get(url, headers=self.headers)
                    response.raise_for_status()
                except exceptions.HTTPError as http_err:
                    raise Exception(f"HTTP ошибка: {http_err}")
                except exceptions.RequestException as err:
                    raise Exception(f"Ошибка запроса: {err}")

                if response.status_code == HTTPStatus.OK:
                    analyse_report = response.json()
                    if analyse_report["data"]["attributes"]["status"] != "completed":
                        time.sleep(5)
                        continue
                    file_id = analyse_report["meta"]["file_info"]["sha256"]
                    report = analyse_report["data"]["attributes"]
                    return file_id, report
                else:
                    raise Exception(f"Ошибка формирования отчета по анализу архива: [statusCode: {response.status_code}] {response.text}")
        except Exception as ex:
            print(f"[☓] {ex}")
            return None


def analyze_file(api_key: str, archive_filename: str, archive_password: str = None, logger: Logger = None) -> dict[str, Any] | None:
    """
    Сбор данных по результату сканирования файла
    {'analyses_id', str} - идентификатор анализа архива
    {'file_id', str} - идентификатор файла SHA-256
    {'detected_avs', dict['antivirus','malware']} - антивирусы обнаружившие уязвимость
    {'threats', dict['malware','antiviruses']} - угроз с ассоциированными антивирусами
    {'hostnames', set} - найденные хосты
    {'resolved_ips', set} - ассоциированные IP адреса
    {'mitre_attack_techniques', dict['id','signature_description']} - детектированные техники атак MITTRE
    :param api_key: ключ авторизации
    :param archive_filename: наименование загружаемого архива в формате zip
    :param archive_password: пароль к защищенному zip архиву при наличии
    :param logger: логгер операций
    :return: справочник с результатом анализа (analyses_id, file_id, detected_avs, threats, hostnames, resolved_ips, mitre_attack_techniques)
    """
    if not api_key or not archive_filename: return None

    try:
        print("Ожидание результатов анализа...")
        print("-" * 31 + "\n")

        # логер
        if not logger: logger = Logger(FileOperationCode.ANALYSE_FILE)
        else: logger.operation = FileOperationCode.ANALYSE_FILE

        # итоговый справочник с результатом анализа
        result = {
            "archive_filename": archive_filename
        }

        # загружаем файл на анализ
        files_api = FilesAPI(api_key, archive_filename, archive_password)
        analyses_id = files_api.upload_file()
        analyses_id = "NjEyYjU3ZTJhZmU3MDY1ZWJlOTIxMzM3MTcwZGY3ZDQ6MTc0MjIzOTg5NQ=="
        if not analyses_id:
            return None
        print(f"{logger.counter}. Архив успешно загружен и просканирован")
        print(f"---> Получен идентификатор анализа архива (analyses_id: {analyses_id})")
        result["analyses_id"] = analyses_id

        # формируем отчет по сканированию файла
        analyses_api = AnalysesAPI(API_KEY, analyses_id)
        analyses_res = analyses_api.analyse_report()
        if not analyses_res:
            return None
        file_id, file_report = analyses_res
        print(f"{logger.counter}. Отчет по анализу архива успешно сформирован")
        print(f"---> Получен идентификатор файла SHA-256 (file_id: {file_id})")
        result["file_id"] = file_id

        # анализ песочницы
        # антивирусы обнаружившие уязвимость
        detected_avs = {}
        results = file_report["results"]
        if results:
            for antivirus, details in results.items():
                if details["category"] == "malicious":
                    detected_avs[antivirus] = details["result"]
            if len(detected_avs) > 0:
                print(f"---> Сформирован список антивирусов обнаруживших уязвимость (detected_avs: {len(detected_avs)})")
                result["detected_avs"] = detected_avs

        # обнаруженные угрозы
        threats = {}
        if detected_avs:
            for avs, malware in detected_avs.items():
                antiviruses = threats.get(malware, set())
                antiviruses.add(avs)
                threats[malware] = antiviruses
            if len(threats) > 0:
                print(f"---> Сформирован список угроз с ассоциированными антивирусами (threats: {len(threats)})")
                result["threats"] = threats

        # анализ поведения (ищем хосты, IP адреса, атаки MITTRE)
        behaviours_report = files_api.behaviours_report(file_id)
        if behaviours_report:
            print(f"{logger.counter}. Отчет о поведении успешно сформирован")
            hostnames = set()  # список найденных хостов
            resolved_ips = set()  # список ассоциированных IP адресов
            mitre_attack_techniques = dict()  # список техник атак MITTRE
            for behaviour in behaviours_report:
                attributes = behaviour["attributes"]
                for attr_tag in ["dns_lookups", "mitre_attack_techniques"]:
                    if attr_tag in attributes:
                        for attr_data in attributes[attr_tag]:
                            # находим имена хостов и IP адреса
                            if attr_tag == "dns_lookups":
                                if "hostname" in attr_data:
                                    hostnames.add(attr_data["hostname"])
                                if "resolved_ips" in attr_data:
                                    resolved_ips.update(attr_data["resolved_ips"])
                            # находим детектированные техники атак MITTRE
                            elif attr_tag == "mitre_attack_techniques":
                                id = attr_data["id"]
                                signature_description = attr_data["signature_description"]
                                mitre_attack_techniques[id] = signature_description
            if len(hostnames) > 0:
                print(f"---> Сформирован список хостов (hostnames: {len(hostnames)})")
                result["hostnames"] = hostnames
            if len(resolved_ips) > 0:
                print(f"---> Сформирован список ассоциированных IP адресов (resolved_ips: {len(resolved_ips)})")
                result["resolved_ips"] = resolved_ips
            if len(mitre_attack_techniques) > 0:
                print(f"---> Сформирован список детектированных техник MITTRE атак (mitre_attack_techniques: {len(mitre_attack_techniques)})")
                result["mitre_attack_techniques"] = mitre_attack_techniques

        return result
    except Exception as ex:
        print(f"[☓] Ошибка сбора данных по результату сканирования файла: {ex}")
        return None

def generate_report(analyse_result: dict[str, Any], output_filename: str = "virus_total_report.txt", target_avs: list | None = None, logger: Logger = None) -> None:
    """
    Генерация отчета по результатам анализа файла
    :param analyse_result: результатом анализа (archive_filename, analyses_id, file_id, detected_avs, threats, hostnames, resolved_ips, mitre_attack_techniques)
    :param output_filename: путь для сохранения файла с отчетом
    :param target_avs: список целевых антивирусов для проверки
    :param logger: логгер операций
    """
    if not analyse_result or not output_filename: return

    try:
        # логер
        if not logger: logger = Logger(FileOperationCode.OUTPUT_REPORT)
        else: logger.operation = FileOperationCode.OUTPUT_REPORT

        filename = analyse_result["archive_filename"]
        analyses_id = analyse_result["analyses_id"]
        file_id = analyse_result["file_id"]
        detected_avs = analyse_result.get("detected_avs", {})
        threats = analyse_result.get("threats", {})
        hostnames = analyse_result.get("hostnames", set())
        resolved_ips = analyse_result.get("resolved_ips", set())
        mitre_attack_techniques = analyse_result.get("mitre_attack_techniques", {})

        with open(output_filename, "w", encoding="utf-8") as file:
            file.write("Отчет анализа файла на наличие киберугроз\n")
            file.write("-" * 41 + "\n\n")

            file.write(f"Файл: {filename}\n")
            file.write(f"Analyses ID: {analyses_id}\n")
            file.write(f"File ID: {file_id}\n")

            if detected_avs:
                file.write(f"\nАнтивирусы обнаружившие уязвимости ({len(detected_avs)}):\n{', '.join(sorted(detected_avs.keys()))}\n")
                if target_avs:
                    file.write("\nПроверка целевых антивирусов:\n")
                    for avs in target_avs:
                        is_detected = avs in detected_avs
                        check_sign = '🗸' if is_detected else '☓'
                        check_text = 'обнаружено' if is_detected else 'не обнаружено'
                        file.write(f"  {u'\u25AA'} {avs}:  {check_sign} {check_text}\n")
            else:
                file.write("\nНет данных по обнаруженным антивирусам\n")

            if threats:
                file.write(f"\nОбнаруженные угрозы ({len(threats)}):\n")
                for threat, avs in sorted(threats.items()):
                    file.write(f"  {u'\u25AA'} [{threat}]: {', '.join(sorted(avs))}\n")
            else:
                file.write("\nНет данных по обнаруженным угрозам\n")

            if hostnames or resolved_ips:
                if hostnames:
                    file.write(f"\nДомены ({len(hostnames)}):\n")
                    for host in sorted(hostnames):
                        file.write(f"  {u'\u25AA'} {host}\n")
                if resolved_ips:
                    file.write(f"\nIP адреса ({len(resolved_ips)}):\n")
                    for ip in resolved_ips:
                        file.write(f"  {u'\u25AA'} {ip}\n")
            else:
                file.write("\nНет данных о сетевой активности\n")

            if mitre_attack_techniques:
                if mitre_attack_techniques:
                    file.write(f"\nMITRE Attack Techniques ({len(mitre_attack_techniques)}):\n")
                    for attack_id, signature_description in sorted(mitre_attack_techniques.items()):
                        file.write(f"  {u'\u25AA'} [{attack_id}]: {signature_description}\n")
            else:
                file.write("\nНет данных по поведению")

            print(f"[{logger.counter}] Сформирован отчет анализа файла на наличие киберугроз: {output_filename}")
    except Exception as ex:
        print(f"[☓] Ошибка формирования отчета анализа файла на наличие киберугроз: {ex}")
        return None


if __name__ == "__main__":
    ARCHIVE_FILENAME = "protected_archive.zip"
    ARCHIVE_PASSWORD = "netology"
    TARGET_AVS = ["Fortinet", "McAfee", "Yandex", "Sophos"]

    try:
        logger = Logger()
        analyse_result = analyze_file(API_KEY, ARCHIVE_FILENAME, ARCHIVE_PASSWORD, logger)
        if analyse_result:
            generate_report(analyse_result, "virus_total_file_report.txt", TARGET_AVS, logger)
    except KeyboardInterrupt:
        print("\nПрервано пользователем...")
    except Exception as ex:
        print(ex)