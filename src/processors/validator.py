"""
اعتبارسنجی پیشرفته کانفیگ‌ها با بررسی امنیتی
"""

import re
import base64
import json
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from src.core.exceptions import ValidationError
from src.security.sanitizer import InputSanitizer


class ConfigValidator:
    """اعتبارسنجی کانفیگ‌های مختلف V2Ray و پروکسی"""
    
    # الگوهای تشخیص
    VMESS_PATTERN = re.compile(r'^vmess://[A-Za-z0-9+/=]+$')
    VLESS_PATTERN = re.compile(r'^vless://[A-Za-z0-9+/=]+$')
    TROJAN_PATTERN = re.compile(r'^trojan://[A-Za-z0-9+/=]+$')
    SS_PATTERN = re.compile(r'^ss://[A-Za-z0-9+/=]+$')
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
    
    def validate(self, config: Any) -> bool:
        """
        اعتبارسنجی اصلی کانفیگ
        
        Args:
            config: کانفیگ به صورت رشته یا دیکشنری
            
        Returns:
            True اگر معتبر باشد
            
        Raises:
            ValidationError: اگر نامعتبر باشد
        """
        try:
            # تشخیص نوع کانفیگ
            if isinstance(config, str):
                return self._validate_string_config(config)
            elif isinstance(config, dict):
                return self._validate_dict_config(config)
            else:
                raise ValidationError("نوع کانفیگ نامشخص")
                
        except Exception as e:
            raise ValidationError(f"خطا در اعتبارسنجی: {str(e)}")
    
    def _validate_string_config(self, config: str) -> bool:
        """اعتبارسنجی کانفیگ رشته‌ای"""
        # پاک‌سازی
        config = self.sanitizer.sanitize_string(config)
        
        # تشخیص پروتکل
        if self.VMESS_PATTERN.match(config):
            return self._validate_vmess_string(config)
        elif self.VLESS_PATTERN.match(config):
            return self._validate_vless_string(config)
        elif self.TROJAN_PATTERN.match(config):
            return self._validate_trojan_string(config)
        elif self.SS_PATTERN.match(config):
            return self._validate_ss_string(config)
        else:
            # فرمت ناشناخته
            return self._validate_unknown_string(config)
    
    def _validate_dict_config(self, config: Dict[str, Any]) -> bool:
        """اعتبارسنجی کانفیگ دیکشنری"""
        # بررسی وجود فیلدهای اصلی
        if 'protocol' in config:
            protocol = config['protocol'].lower()
            
            if protocol == 'vmess':
                return self._validate_vmess_dict(config)
            elif protocol == 'vless':
                return self._validate_vless_dict(config)
            elif protocol == 'trojan':
                return self._validate_trojan_dict(config)
            elif protocol == 'shadowsocks':
                return self._validate_ss_dict(config)
        
        # تشخیص خودکار
        if 'v' in config and 'ps' in config and 'add' in config:
            return self._validate_vmess_dict(config)
        elif 'password' in config and 'host' in config:
            return self._validate_trojan_dict(config)
        elif 'server' in config and 'method' in config:
            return self._validate_ss_dict(config)
        
        raise ValidationError("ساختار کانفیگ نامشخص")
    
    def _validate_vmess_string(self, config: str) -> bool:
        """اعتبارسنجی VMESS رشته‌ای"""
        try:
            # استخراج بخش Base64
            base64_part = config.split('vmess://')[1]
            decoded = base64.b64decode(base64_part).decode('utf-8')
            data = json.loads(decoded)
            return self._validate_vmess_dict(data)
        except Exception:
            return False
    
    def _validate_vmess_dict(self, data: Dict[str, Any]) -> bool:
        """اعتبارسنجی VMESS دیکشنری"""
        required_fields = ['v', 'ps', 'add', 'port', 'id', 'aid']
        
        # بررسی فیلدهای اجباری
        for field in required_fields:
            if field not in data:
                return False
        
        # اعتبارسنجی پورت
        try:
            port = int(data['port'])
            if not (1 <= port <= 65535):
                return False
        except (ValueError, TypeError):
            return False
        
        # اعتبارسنجی آدرس
        if not self._validate_address(data['add']):
            return False
        
        # اعتبارسنجی UUID
        if not self._validate_uuid(data['id']):
            return False
        
        return True
    
    def _validate_vless_string(self, config: str) -> bool:
        """اعتبارسنجی VLESS رشته‌ای"""
        try:
            # VLESS معمولاً به فرمت URL با پارامترهاست
            parsed = urlparse(config)
            
            if not parsed.hostname or not parsed.port:
                return False
            
            # اعتبارسنجی پورت
            try:
                port = int(parsed.port)
                if not (1 <= port <= 65535):
                    return False
            except (ValueError, TypeError):
                return False
            
            # اعتبارسنجی UUID از path
            path = parsed.path.strip('/')
            if path and not self._validate_uuid(path):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _validate_vless_dict(self, data: Dict[str, Any]) -> bool:
        """اعتبارسنجی VLESS دیکشنری"""
        required_fields = ['v', 'ps', 'add', 'port', 'id']
        
        for field in required_fields:
            if field not in data:
                return False
        
        # مشابه VMESS
        try:
            port = int(data['port'])
            if not (1 <= port <= 65535):
                return False
        except (ValueError, TypeError):
            return False
        
        if not self._validate_address(data['add']):
            return False
        
        if not self._validate_uuid(data['id']):
            return False
        
        return True
    
    def _validate_trojan_string(self, config: str) -> bool:
        """اعتبارسنجی Trojan رشته‌ای"""
        try:
            parsed = urlparse(config)
            
            if not parsed.hostname or not parsed.port:
                return False
            
            # اعتبارسنجی پورت
            try:
                port = int(parsed.port)
                if not (1 <= port <= 65535):
                    return False
            except (ValueError, TypeError):
                return False
            
            # بررسی SNI
            if 'sni' in parsed.query:
                sni = parse_qs(parsed.query).get('sni', [''])[0]
                if not self._validate_sni(sni):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _validate_trojan_dict(self, data: Dict[str, Any]) -> bool:
        """اعتبارسنجی Trojan دیکشنری"""
        required_fields = ['password', 'host', 'port']
        
        for field in required_fields:
            if field not in data:
                return False
        
        try:
            port = int(data['port'])
            if not (1 <= port <= 65535):
                return False
        except (ValueError, TypeError):
            return False
        
        if not self._validate_address(data['host']):
            return False
        
        if 'sni' in data and not self._validate_sni(data['sni']):
            return False
        
        return True
    
    def _validate_ss_string(self, config: str) -> bool:
        """اعتبارسنجی Shadowsocks رشته‌ای"""
        try:
            base64_part = config.split('ss://')[1]
            # گاهی اوقات بخش دوم رمزگذاری شده است
            decoded = base64.b64decode(base64_part).decode('utf-8')
            return True
        except Exception:
            return False
    
    def _validate_ss_dict(self, data: Dict[str, Any]) -> bool:
        """اعتبارسنجی Shadowsocks دیکشنری"""
        required_fields = ['server', 'port', 'method', 'password']
        
        for field in required_fields:
            if field not in data:
                return False
        
        try:
            port = int(data['port'])
            if not (1 <= port <= 65535):
                return False
        except (ValueError, TypeError):
            return False
        
        if not self._validate_address(data['server']):
            return False
        
        # بررسی متود
        valid_methods = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']
        if data['method'] not in valid_methods:
            return False
        
        return True
    
    def _validate_unknown_string(self, config: str) -> bool:
        """اعتبارسنجی فرمت‌های ناشناخته"""
        # حداقل طول
        if len(config) < 20:
            return False
        
        # بررسی وجود کاراکترهای غیرمجاز
        if not re.match(r'^[A-Za-z0-9+/=:?&@\.\-_]+$', config):
            return False
        
        return True
    
    def _validate_address(self, address: str) -> bool:
        """اعتبارسنجی آدرس (IP یا دامنه)"""
        if not address or len(address) > 255:
            return False
        
        # پاک‌سازی
        address = self.sanitizer.sanitize_string(address)
        
        # بررسی IP
        if self.sanitizer.validate_ip(address):
            return True
        
        # بررسی دامنه
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, address):
            return True
        
        return False
    
    def _validate_uuid(self, uuid: str) -> bool:
        """اعتبارسنجی UUID"""
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(uuid_pattern, uuid.lower()))
    
    def _validate_sni(self, sni: str) -> bool:
        """اعتبارسنجی SNI"""
        if not sni:
            return True
        
        # SNI باید دامنه معتبر باشد
        return self._validate_address(sni)