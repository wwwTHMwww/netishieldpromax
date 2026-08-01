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
                if response.status != 200:
                    result["error"] = f"HTTP {response.status}"
                    return result
                
                # بررسی سایز
                content = await response.text()
                result["size"] = len(content.encode('utf-8'))
                
                if result["size"] > settings.security.max_request_size:
                    result["error"] = "سایز پاسخ بیش از حد مجاز"
                    return result
                
                # پاک‌سازی محتوا
                result["data"] = InputSanitizer.sanitize_string(content)
                result["success"] = True
                
                # محاسبه زمان پاسخ
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                result["response_time"] = elapsed
                
                # لاگ موفقیت
                logger.debug(f"دریافت موفق از {source.name}: {result['size']} bytes")
                
        except asyncio.TimeoutError:
            result["error"] = f"تایم‌اوت {source.timeout} ثانیه"
            raise TimeoutError(source.name, source.timeout)
            
        except aiohttp.ClientError as e:
            result["error"] = f"خطای HTTP: {str(e)}"
            raise SourceError(f"خطای اتصال: {str(e)}", source.name)
            
        except Exception as e:
            result["error"] = str(e)
            raise SourceError(f"خطای غیرمنتظره: {str(e)}", source.name)
            
        finally:
            # لاگ امنیتی
            audit_logger.log_security_event(
                "source_fetch",
                {
                    "source": source.name,
                    "success": result["success"],
                    "status_code": result["status_code"],
                    "size": result["size"],
                    "error": result["error"]
                }
            )
        
        return result
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        """اجرای مرحله دریافت"""
        logger.info(f"مرحله دریافت: {len(context.sources)} منبع")
        
        await self._create_session()
        
        try:
            # دریافت همزمان از همه منابع
            tasks = [self._fetch_source(source) for source in context.sources]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # پردازش نتایج
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"خطا در دریافت: {str(result)}")
                    continue
                
                if result["success"]:
                    context.raw_data[result["source"]] = result["data"]
                    context.metadata["source_stats"][result["source"]] = {
                        "status": "success",
                        "size": result["size"],
                        "response_time": result["response_time"]
                    }
                else:
                    logger.warning(f"دریافت ناموفق {result['source']}: {result['error']}")
                    context.metadata["source_stats"][result["source"]] = {
                        "status": "failed",
                        "error": result["error"]
                    }
            
            # آمار
            success_count = len(context.raw_data)
            logger.info(f"دریافت موفق: {success_count}/{len(context.sources)}")
            
        finally:
            await self.session.close()
        
        return context


class ParseStage(PipelineStage):
    """مرحله پردازش و استخراج کانفیگ"""
    
    def __init__(self):
        super().__init__("parse")
        self.adapter_factory = AdapterFactory()
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        """اجرای مرحله پردازش"""
        logger.info("مرحله پردازش: استخراج کانفیگ‌ها")
        
        total_configs = 0
        
        for source_name, raw_data in context.raw_data.items():
            try:
                # پیدا کردن منبع مربوطه
                source = next(
                    (s for s in context.sources if s.name == source_name),
                    None
                )
                
                if not source:
                    continue
                
                # ایجاد آداپتور مناسب
                adapter = self.adapter_factory.create(
                    source.type,
                    source.parser_config or {}
                )
                
                # پردازش داده
                parsed_configs = adapter.parse(raw_data)
                
                if parsed_configs:
                    context.parsed_data[source_name] = parsed_configs
                    total_configs += len(parsed_configs)
                    
                    logger.debug(f"استخراج {len(parsed_configs)} کانفیگ از {source_name}")
                else:
                    logger.warning(f"هیچ کانفیگی از {source_name} استخراج نشد")
                    
            except Exception as e:
                logger.error(f"خطا در پردازش {source_name}: {str(e)}")
                context.errors.append({
                    "source": source_name,
                    "error": str(e),
                    "stage": "parse"
                })
        
        logger.info(f"مجموع کانفیگ‌های استخراج شده: {total_configs}")
        context.metadata["stats"]["parsed_configs"] = total_configs
        
        return context


class ValidateStage(PipelineStage):
    """مرحله اعتبارسنجی کانفیگ‌ها"""
    
    def __init__(self):
        super().__init__("validate")
        self.validator = ConfigValidator()
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        """اجرای مرحله اعتبارسنجی"""
        logger.info("مرحله اعتبارسنجی: بررسی کیفیت کانفیگ‌ها")
        
        total_valid = 0
        total_invalid = 0
        
        for source_name, configs in context.parsed_data.items():
            valid_configs = []
            
            for config in configs:
                try:
                    if self.validator.validate(config):
                        valid_configs.append(config)
                        total_valid += 1
                    else:
                        total_invalid += 1
                except ValidationError as e:
                    total_invalid += 1
                    logger.debug(f"کانفیگ نامعتبر از {source_name}: {str(e)}")
            
            # بروزرسانی با کانفیگ‌های معتبر
            context.parsed_data[source_name] = valid_configs
        
        logger.info(f"کانفیگ‌های معتبر: {total_valid}، نامعتبر: {total_invalid}")
        context.metadata["stats"]["valid_configs"] = total_valid
        context.metadata["stats"]["invalid_configs"] = total_invalid
        
        return context


class DeduplicateStage(PipelineStage):
    """مرحله حذف کانفیگ‌های تکراری"""
    
    def __init__(self):
        super().__init__("deduplicate")
        self.deduplicator = Deduplicator()
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        """اجرای مرحله حذف تکراری"""
        logger.info("مرحله حذف تکراری")
        
        # جمع‌آوری همه کانفیگ‌ها
        all_configs = []
        for configs in context.parsed_data.values():
            all_configs.extend(configs)
        
        # حذف تکراری
        unique_configs, duplicates = self.deduplicator.deduplicate(all_configs)
        
        logger.info(f"حذف {len(duplicates)} کانفیگ تکراری از {len(all_configs)} کانفیگ")
        
        # بازسازی داده
        context.processed_data = unique_configs
        context.metadata["stats"]["deduplicated_configs"] = len(unique_configs)
        context.metadata["stats"]["duplicates_removed"] = len(duplicates)
        
        return context


class RankStage(PipelineStage):
    """مرحله رتبه‌بندی کانفیگ‌ها"""
    
    def __init__(self):
        super().__init__("rank")
        self.ranker = Ranker()
    
    async def process(self, context: PipelineContext) -> PipelineContext:
        """اجرای مرحله رتبه‌بندی"""
        logger.info("مرحله رتبه‌بندی: انتخاب بهترین کانفیگ‌ها")
        
        if not context.processed_data:
            logger.warning("هیچ کانفیگی برای رتبه‌بندی وجود ندارد")
            return context
        
        # رتبه‌بندی
        ranked_configs = self.ranker.rank(
            context.processed_data,
            max_configs=settings.security.max_configs
        )
        
        context.processed_data = ranked_configs
        context.metadata["stats"]["ranked_configs"] = len(ranked_configs)
        
        logger.info(f"انتخاب {len(ranked_configs)} کانفیگ برتر")
        
        return context


class Pipeline:
    """خط لوله اصلی پردازش"""
    
    def __init__(self):
        self.stages = [
            FetchStage(),
            ParseStage(),
            ValidateStage(),
            DeduplicateStage(),
            RankStage()
        ]
        self.cache = CacheManager()
        self.metrics = MetricsCollector()
    
    @handle_errors(reraise=True)
    async def execute(self, sources: List[SourceConfig]) -> PipelineContext:
        """
        اجرای کامل خط لوله
        
        Args:
            sources: لیست منابع
            
        Returns:
            Context نهایی با داده‌های پردازش شده
        """
        logger.info("شروع اجرای خط لوله NetiShield Pro")
        
        # ایجاد Context
        context = PipelineContext(
            sources=sources,
            start_time=datetime.utcnow()
        )
        
        try:
            # اجرای مرحله به مرحله
            for stage in self.stages:
                start = datetime.utcnow()
                context = await stage.process(context)
                elapsed = (datetime.utcnow() - start).total_seconds()
                
                logger.debug(f"مرحله {stage.name} در {elapsed:.2f} ثانیه")
                context.metadata["timing"][stage.name] = elapsed
            
            # ثبت متریک‌ها
            context.metadata["end_time"] = datetime.utcnow().isoformat() + "Z"
            total_time = (datetime.utcnow() - context.start_time).total_seconds()
            context.metadata["total_time"] = total_time
            
            # ذخیره در کش
            if context.processed_data:
                await self.cache.set(
                    "last_processed_configs",
                    context.processed_data,
                    ttl=settings.security.rate_limit_window
                )
            
            logger.info(f"خط لوله با موفقیت در {total_time:.2f} ثانیه تکمیل شد")
            
        except NetiShieldException as e:
            logger.error(f"خطا در خط لوله: {str(e)}")
            audit_logger.log_security_event(
                "pipeline_failure",
                {
                    "error": str(e),
                    "severity": e.severity.value,
                    "details": e.details
                },
                ErrorSeverity.ERROR
            )
            raise
            
        except Exception as e:
            logger.critical(f"خطای غیرمنتظره در خط لوله: {str(e)}")
            raise NetiShieldException(f"خطای سیستم: {str(e)}")
        
        # ذخیره متریک‌ها
        await self.metrics.save(context.metadata)
        
        return context