"""
خط لوله اصلی پردازش با امنیت و مدیریت خطا
"""

import asyncio
import aiohttp
import aiohttp.client_exceptions
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from src.core.context import PipelineContext
from src.core.exceptions import (
    NetiShieldException,
    SourceError,
    ParseError,
    ValidationError,
    TimeoutError,
    handle_errors
)
from src.config.settings import SourceConfig, settings
from src.adapters.factory import AdapterFactory
from src.processors.validator import ConfigValidator
from src.processors.deduplicator import Deduplicator
from src.processors.normalizer import Normalizer
from src.processors.ranker import Ranker
from src.security.sanitizer import InputSanitizer
from src.utils.logger import logger, audit_logger
from src.utils.cache import CacheManager
from src.utils.metrics import MetricsCollector


class PipelineStage:
    """کلاس پایه برای مراحل خط لوله"""
    
    def __init__(self, name: str):
        self.name = name
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        raise NotImplementedError


class FetchStage(PipelineStage):
    """مرحله دریافت داده از منابع"""
    
    def __init__(self):
        super().__init__("fetch")
        self.session: Optional[aiohttp.ClientSession] = None
        self.timeout = aiohttp.ClientTimeout(total=settings.security.max_request_size)
    
    async def _create_session(self):
        """ایجاد session با تنظیمات امنیتی"""
        connector = aiohttp.TCPConnector(
            limit=10,  # تعداد اتصالات همزمان
            limit_per_host=5,
            ttl_dns_cache=300,
            ssl=True,
            force_close=True
        )
        
        headers = {
            "User-Agent": "NetiShield-Pro/2.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "fa-IR,fa;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=headers,
            raise_for_status=False
        )
    
    async def _fetch_source(self, source: SourceConfig) -> Dict[str, Any]:
        """دریافت داده از یک منبع با امنیت کامل"""
        result = {
            "source": source.name,
            "url": source.url,
            "success": False,
            "data": None,
            "error": None,
            "status_code": None,
            "response_time": None,
            "size": 0
        }
        
        try:
            # پاک‌سازی URL
            clean_url = InputSanitizer.sanitize_url(str(source.url))
            
            # آماده‌سازی هدرها
            headers = InputSanitizer.sanitize_headers(source.headers or {})
            
            start_time = datetime.utcnow()
            
            # درخواست با ریت‌لایمیت
            async with self.session.get(
                clean_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=source.timeout)
            ) as response:
                result["status_code"] = response.status
                
                # بررسی وضعیت
                if response