import re
import logging


class SensitiveDataRedactor(logging.Filter):
    """
    BUG FIXED: the original PATTERNS dict (api_key / password) was built but
    never actually applied inside filter() — only an inline tax-id regex ran.
    That meant API keys and passwords could leak into logs verbatim. Now all
    patterns are applied, and the substitution keeps the key name for context
    while redacting the value.
    """

    PATTERNS = {
        "api_key": re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', re.I),
        "password": re.compile(r'(password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', re.I),
        "authorization": re.compile(r'(authorization["\']?\s*[:=]\s*["\']?)(Bearer\s+)?([^"\'}\s]+)', re.I),
    }
    TAX_ID_PATTERN = re.compile(r'\b[A-Z]{2}\d{8,12}\b')

    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.getMessage() if record.args else record.msg)

        msg = self.PATTERNS["api_key"].sub(r"\1[REDACTED]", msg)
        msg = self.PATTERNS["password"].sub(r"\1[REDACTED]", msg)
        msg = self.PATTERNS["authorization"].sub(r"\1[REDACTED]", msg)
        msg = self.TAX_ID_PATTERN.sub("[TAX_ID_REDACTED]", msg)

        record.msg = msg
        record.args = ()  # args already interpolated into msg above
        return True
