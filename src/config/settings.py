"""
تنظیمات اصلی پروژه با Pydantic - اعتبارسنجی خودکار و امن
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseSettings, Field, validator, SecretStr, HttpUrl
from pydantic.networks import AnyHttpUrl
import os
from pathlib import Path
import logging

class SourceConfig(BaseSettings):
    """تنظیمات هر منبع با اعتبارسنجی امنیتی"""
    
    name: str = Field(..., min_length=3, max_length=50, description="نام منبع")
    url: AnyHttpUrl = Field(..., description="آدرس منبع (فقط HTTPS در تولید)")
    type: str = Field(..., regex="^(v2ray|json|web|custom)$", description="نوع منبع")
    enabled: bool = Field(default=True)
    timeout: int = Field(default=30, ge=5, le=120, description="تایم‌اوت ثانیه")
    max_retries: int = Field(default=3, ge=1, le=5)
    
    # هدرهای HTTP با امنیت
    headers: Optional[Dict[str, str]] = Field(
        default_factory=lambda: {
            "User-Agent": "NetiShield-Pro/2.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }
    )
    
    # تنظیمات اختصاصی هر نوع منبع
    parser_config: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    # اعتبارسنجی امنیتی URL
    @validator('url')
    def validate_url_security(cls, v):
        """بررسی امنیت URL"""
        # جلوگیری از SSRF
        forbidden_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if any(domain in v.host for domain in forbidden_domains):
            raise ValueError(f"آدرس {v.host} غیرمجاز است (احتمال SSRF)")
        
        # فقط HTTPS در محیط تولید
        if os.getenv('ENV') == 'production' and v.scheme != 'https':
            raise ValueError("در محیط تولید فقط HTTPS مجاز است")
        
        return v
    
    class Config:
        env_prefix = "SOURCE_"
        extra = "forbid"  # جلوگیری از فیلدهای اضافی


class OutputConfig(BaseSettings):
    """تنظیمات خروجی"""
    
    type: str = Field(..., regex="^(txt|json|yaml|api)$")
    path: Optional[str] = Field(None, description="مسیر ذخیره فایل")
    format: Optional[Dict[str, Any]] = Field(default_factory=dict)
    max_size: int = Field(default=10_000_000, description="حداکثر سایز خروجی (بایت)")
    
    @validator('path')
    def validate_path(cls, v, values):
        """اعتبارسنجی مسیر فایل"""
        if values.get('type') != 'api' and not v:
            raise ValueError("برای خروجی غیر API باید مسیر مشخص شود")
        
        if v:
            # جلوگیری از Path Traversal
            path = Path(v)
            if '..' in path.parts:
                raise ValueError("مسیر حاوی '..' غیرمجاز است")
            
            # اطمینان از وجود دایرکتوری
            path.parent.mkdir(parents=True, exist_ok=True)
        
        return v
    
    class Config:
        extra = "forbid"


class SecurityConfig(BaseSettings):
    """تنظیمات امنیتی"""
    
    # رمزنگاری
    encryption_key: SecretStr = Field(..., env='ENCRYPTION_KEY')
    jwt_secret: SecretStr = Field(..., env='JWT_SECRET')
    
    # محدودیت‌ها
    max_configs: int = Field(default=1000, ge=10, le=10000)
    max_request_size: int = Field(default=10_485_760, description="حداکثر سایز درخواست (10MB)")
    
    # CORS (برای API)
    cors_origins: List[str] = Field(
        default_factory=lambda: ["https://localhost:3000", "https://netishield.ir"]
    )
    
    # Rate Limiting
    rate_limit_requests: int = Field(default=100, description="تعداد درخواست در دقیقه")
    rate_limit_window: int = Field(default=60, description="پنجره زمانی (ثانیه)")
    
    # امنیت سربرگ‌ها
    security_headers: Dict[str, str] = Field(
        default_factory=lambda: {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        }
    )
    
    # مجوزها
    allowed_ips: Optional[List[str]] = Field(None, description="IP‌های مجاز (خالی = همه)")
    blocked_ips: List[str] = Field(default_factory=list, description="IP‌های مسدود شده")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "forbid"


class LoggingConfig(BaseSettings):
    """تنظیمات لاگ‌گیری"""
    
    level: str = Field(default="INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    file: Optional[str] = Field(default="logs/app.log")
    max_size: int = Field(default=10_485_760, description="حداکثر سایز هر فایل لاگ (10MB)")
    backup_count: int = Field(default=5, description="تعداد فایل‌های پشتیبان")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    # لاگ امنیتی جداگانه
    security_log: str = Field(default="logs/security.log")
    
    @validator('file', 'security_log')
    def validate_log_path(cls, v):
        if v:
            path = Path(v)
            if '..' in path.parts:
                raise ValueError("مسیر لاگ غیرمجاز است")
            path.parent.mkdir(parents=True, exist_ok=True)
        return v
    
    class Config:
        env_prefix = "LOG_"
        extra = "forbid"


class Settings(BaseSettings):
    """تنظیمات اصلی با تجمیع همه بخش‌ها"""
    
    # محیط
    env: str = Field(default="development", regex="^(development|staging|production)$")
    debug: bool = Field(default=True)
    
    # بخش‌ها
    sources: List[SourceConfig] = Field(..., min_items=1)
    outputs: List[OutputConfig] = Field(..., min_items=1)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # تنظیمات عمومی
    update_interval: int = Field(default=1800, ge=300, le=86400, description="فاصله بروزرسانی (ثانیه)")
    timezone: str = Field(default="Asia/Tehran")
    
    @validator('debug')
    def validate_debug(cls, v, values):
        """غیرفعال کردن Debug در تولید"""
        if values.get('env') == 'production' and v:
            raise ValueError("در محیط تولید Debug باید False باشد")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "forbid"


# نمونه تنظیمات
settings = Settings()