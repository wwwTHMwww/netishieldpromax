"""
سیستم ممیزی امنیتی پیشرفته
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from collections import defaultdict
import hashlib
import hmac
from src.core.exceptions import SecurityError
from src.utils.logger import logger


class AuditTrail:
    """ثبت و بررسی رویدادهای امنیتی"""
    
    def __init__(self, log_file: str = "logs/audit.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._cache: List[Dict] = []
        self._max_cache = 100
    
    def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "INFO"
    ):
        """ثبت رویداد امنیتی"""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "hash": self._calculate_hash(event_type, details)
        }
        
        # ذخیره در کش
        self._cache.append(event)
        if len(self._cache) > self._max_cache:
            self._flush_cache()
        
        # ذخیره فوری در فایل
        self._write_to_file(event)
    
    def _flush_cache(self):
        """ذخیره کش در فایل"""
        for event in self._cache:
            self._write_to_file(event)
        self._cache.clear()
    
    def _write_to_file(self, event: Dict):
        """نوشتن رویداد در فایل"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"خطا در ذخیره ممیزی: {str(e)}")
    
    def _calculate_hash(self, event_type: str, details: Dict) -> str:
        """محاسبه هش برای یکپارچگی"""
        data = f"{event_type}{json.dumps(details, sort_keys=True)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """دریافت رویدادهای امنیتی"""
        events = []
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if len(events) >= limit:
                        break
                    try:
                        event = json.loads(line)
                        
                        # فیلتر
                        if event_type and event['event_type'] != event_type:
                            continue
                        if severity and event['severity'] != severity:
                            continue
                        
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        return events


class SecurityChecker:
    """بررسی مسائل امنیتی"""
    
    def __init__(self):
        self.audit = AuditTrail()
    
    def check_config_security(self, config: Dict[str, Any]) -> List[str]:
        """بررسی امنیت کانفیگ"""
        issues = []
        
        # بررسی رمزهای ضعیف
        if 'id' in config:
            if self._is_weak_uuid(config['id']):
                issues.append("UUID ضعیف: احتمالاً قابل حدس زدن")
        
        if 'password' in config:
            if self._is_weak_password(config['password']):
                issues.append("پسورد ضعیف: طول کافی یا پیچیدگی ندارد")
        
        if 'method' in config:
            if self._is_weak_encryption(config['method']):
                issues.append(f"روش رمزنگاری ضعیف: {config['method']}")
        
        return issues
    
    def _is_weak_uuid(self, uuid: str) -> bool:
        """بررسی UUID ضعیف"""
        # مثال: تمام صفر یا الگوی تکراری
        weak_patterns = [
            '00000000-0000-0000-0000-000000000000',
            '11111111-1111-1111-1111-111111111111',
            '12345678-1234-1234-1234-123456789012'
        ]
        return uuid.lower() in weak_patterns
    
    def _is_weak_password(self, password: str) -> bool:
        """بررسی پسورد ضعیف"""
        if len(password) < 8:
            return True
        
        # بررسی پسوردهای رایج
        common_passwords = ['password', '12345678', 'qwerty123', 'admin123']
        return password.lower() in common_passwords
    
    def _is_weak_encryption(self, method: str) -> bool:
        """بررسی روش رمزنگاری ضعیف"""
        weak_methods = ['none', 'plain', 'aes-128-cfb', 'rc4-md5']
        return method.lower() in weak_methods
    
    def check_source_security(self, url: str) -> Dict[str, bool]:
        """بررسی امنیت منبع"""
        checks = {
            "https": url.startswith("https://"),
            "no_ip": not self._is_ip_address(url),
            "no_private_ip": not self._is_private_ip(url),
            "no_localhost": "localhost" not in url.lower()
        }
        return checks
    
    def _is_ip_address(self, url: str) -> bool:
        """بررسی IP بودن"""
        import re
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return bool(re.search(ip_pattern, url))
    
    def _is_private_ip(self, url: str) -> bool:
        """بررسی IP خصوصی"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.'
        ]
        return any(url.startswith(ip_range) for ip_range in private_ranges)


# نمونه‌های تکی
audit_trail = AuditTrail()
security_checker = SecurityChecker()