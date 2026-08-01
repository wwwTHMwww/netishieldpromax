"""
سیستم لاگ‌گیری پیشرفته با امنیت و روتیشن
"""

import logging
import logging.handlers
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from src.config.settings import settings
from src.core.exceptions import ErrorSeverity


class SecurityFilter(logging.Filter):
    """فیلتر امنیتی برای جلوگیری از لاگ شدن اطلاعات حساس"""
    
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'key',
        'authorization', 'auth', 'cookie', 'session', 'jwt',
        'credit', 'card', 'cvv', 'pin', 'private'
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        # پنهان کردن اطلاعات حساس در پیام
        msg = record.getMessage()
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in msg.lower():
                record.msg = record.msg.replace(pattern, '***')
                record.args = tuple(
                    arg.replace(pattern, '***') 
                    if isinstance(arg, str) and pattern in arg.lower() 
                    else arg 
                    for arg in record.args
                )
        return True


class JsonFormatter(logging.Formatter):
    """فرمت‌کننده JSON برای لاگ‌ها"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
        }
        
        # اضافه کردن exception اگر وجود دارد
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # اضافه کردن اطلاعات اضافی
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data, ensure_ascii=False)


def setup_logger(
    name: str = "netishield",
    log_level: Optional[str] = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    راه‌اندازی لاگر با تنظیمات امنیتی
    
    Args:
        name: نام لاگر
        log_level: سطح لاگ (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: مسیر فایل لاگ
        
    Returns:
        نمونه Logger
    """
    # تنظیمات از settings
    log_config = settings.logging
    level = log_level or log_config.level
    log_file = log_file or log_config.file
    
    # ایجاد لاگر
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # جلوگیری از اضافه شدن دسته‌های تکراری
    if logger.handlers:
        logger.handlers.clear()
    
    # فرمت‌کننده
    formatter = JsonFormatter()
    
    # هندلر کنسول
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SecurityFilter())
    logger.addHandler(console_handler)
    
    # هندلر فایل با روتیشن
    if log_file:
        try:
            # اطمینان از وجود دایرکتوری
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            
            # روتیشن با حجم فایل
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=log_config.max_size,
                backupCount=log_config.backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            file_handler.addFilter(SecurityFilter())
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"خطا در ایجاد فایل لاگ: {e}")
    
    # لاگ امنیتی جداگانه
    if log_config.security_log:
        try:
            security_path = Path(log_config.security_log)
            security_path.parent.mkdir(parents=True, exist_ok=True)
            
            security_handler = logging.handlers.RotatingFileHandler(
                log_config.security_log,
                maxBytes=log_config.max_size,
                backupCount=log_config.backup_count,
                encoding='utf-8'
            )
            security_handler.setFormatter(formatter)
            security_handler.setLevel(logging.WARNING)
            security_handler.addFilter(SecurityFilter())
            
            # لاگر مخصوص امنیت
            security_logger = logging.getLogger(f"{name}.security")
            security_logger.setLevel(logging.WARNING)
            security_logger.addHandler(security_handler)
        except Exception as e:
            logger.error(f"خطا در ایجاد لاگ امنیتی: {e}")
    
    return logger


class AuditLogger:
    """لاگ‌گیری رویدادهای امنیتی و مدیریتی"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: ErrorSeverity = ErrorSeverity.INFO
    ):
        """لاگ رویداد امنیتی"""
        log_data = {
            "event_type": event_type,
            "severity": severity.value,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details
        }
        
        # استفاده از لاگر مخصوص امنیت
        security_logger = logging.getLogger(f"{self.logger.name}.security")
        security_logger.warning(json.dumps(log_data, ensure_ascii=False))
    
    def log_user_action(
        self,
        user_id: str,
        action: str,
        resource: str,
        success: bool,
        details: Optional[Dict] = None
    ):
        """لاگ اقدامات کاربر"""
        log_data = {
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "success": success,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details or {}
        }
        
        self.logger.info(json.dumps(log_data, ensure_ascii=False))
    
    def log_system_event(
        self,
        event: str,
        status: str,
        details: Optional[Dict] = None
    ):
        """لاگ رویدادهای سیستمی"""
        log_data = {
            "event": event,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details or {}
        }
        
        self.logger.info(json.dumps(log_data, ensure_ascii=False))


# نمونه لاگر
logger = setup_logger()
audit_logger = AuditLogger(logger)