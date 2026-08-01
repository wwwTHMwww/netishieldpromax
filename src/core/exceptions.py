"""
استثناهای سفارشی و سیستم مدیریت خطا
"""

from typing import Optional, Any, Dict
from enum import Enum


class ErrorSeverity(Enum):
    """سطح شدت خطا"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class NetiShieldException(Exception):
    """کلاس پایه استثناها"""
    
    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        details: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None
    ):
        self.message = message
        self.severity = severity
        self.details = details or {}
        self.source = source
        super().__init__(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """تبدیل به دیکشنری برای لاگ‌گیری"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "severity": self.severity.value,
            "details": self.details,
            "source": self.source
        }


class ConfigurationError(NetiShieldException):
    """خطای تنظیمات"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(f"خطای تنظیمات: {message}", ErrorSeverity.CRITICAL, details)


class SecurityError(NetiShieldException):
    """خطای امنیتی (لاگ مهم)"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(f"خطای امنیتی: {message}", ErrorSeverity.CRITICAL, details)


class SourceError(NetiShieldException):
    """خطای منبع"""
    def __init__(self, message: str, source: str, details: Optional[Dict] = None):
        super().__init__(
            f"خطای منبع {source}: {message}",
            ErrorSeverity.ERROR,
            details,
            source
        )


class ParseError(NetiShieldException):
    """خطای پردازش"""
    def __init__(self, message: str, source: str, details: Optional[Dict] = None):
        super().__init__(
            f"خطای پردازش: {message}",
            ErrorSeverity.ERROR,
            details,
            source
        )


class ValidationError(NetiShieldException):
    """خطای اعتبارسنجی"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(f"خطای اعتبارسنجی: {message}", ErrorSeverity.WARNING, details)


class RateLimitError(NetiShieldException):
    """خطای محدودیت نرخ"""
    def __init__(self, message: str = "محدودیت نرخ درخواست", details: Optional[Dict] = None):
        super().__init__(message, ErrorSeverity.WARNING, details)


class TimeoutError(NetiShieldException):
    """خطای تایم‌اوت"""
    def __init__(self, source: str, timeout: int):
        super().__init__(
            f"تایم‌اوت {timeout} ثانیه برای منبع {source}",
            ErrorSeverity.ERROR,
            {"timeout": timeout},
            source
        )


class DataCorruptionError(NetiShieldException):
    """خطای خرابی داده"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(f"خرابی داده: {message}", ErrorSeverity.ERROR, details)


# دکوراتور برای مدیریت خطاها
def handle_errors(
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    reraise: bool = False
):
    """دکوراتور برای مدیریت خودکار خطاها"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except NetiShieldException:
                raise
            except Exception as e:
                error = NetiShieldException(
                    f"خطای غیرمنتظره در {func.__name__}: {str(e)}",
                    severity
                )
                if reraise:
                    raise error
                return None
        return wrapper
    return decorator