"""
Date and time utilities for the Dynamic Honeypot Platform.
Provides timezone-aware datetime handling and formatting.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union
import pytz


class DateUtils:
    """Date and time utility functions."""
    
    UTC = timezone.utc
    
    @staticmethod
    def now() -> datetime:
        """
        Get current UTC datetime.
        
        Returns:
            Current UTC datetime
        """
        return datetime.now(DateUtils.UTC)
    
    @staticmethod
    def from_timestamp(timestamp: Union[int, float]) -> datetime:
        """
        Convert timestamp to UTC datetime.
        
        Args:
            timestamp: Unix timestamp
            
        Returns:
            UTC datetime
        """
        return datetime.fromtimestamp(timestamp, tz=DateUtils.UTC)
    
    @staticmethod
    def to_timestamp(dt: datetime) -> int:
        """
        Convert datetime to Unix timestamp.
        
        Args:
            dt: Datetime object
            
        Returns:
            Unix timestamp
        """
        return int(dt.timestamp())
    
    @staticmethod
    def from_iso_string(iso_string: str) -> Optional[datetime]:
        """
        Parse ISO 8601 string to datetime.
        
        Args:
            iso_string: ISO 8601 formatted string
            
        Returns:
            Datetime object or None if parsing fails
        """
        try:
            # Handle 'Z' suffix for UTC
            if iso_string.endswith('Z'):
                iso_string = iso_string[:-1] + '+00:00'
            return datetime.fromisoformat(iso_string)
        except (ValueError, AttributeError):
            return None
    
    @staticmethod
    def to_iso_string(dt: datetime) -> str:
        """
        Format datetime as ISO 8601 string.
        
        Args:
            dt: Datetime object
            
        Returns:
            ISO 8601 formatted string
        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=DateUtils.UTC)
        return dt.isoformat()
    
    @staticmethod
    def format_duration(seconds: Union[int, float]) -> str:
        """
        Format duration in seconds to human-readable string.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string
        """
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f}h"
        else:
            days = seconds / 86400
            return f"{days:.1f}d"
    
    @staticmethod
    def add_seconds(dt: datetime, seconds: Union[int, float]) -> datetime:
        """
        Add seconds to datetime.
        
        Args:
            dt: Datetime object
            seconds: Seconds to add
            
        Returns:
            New datetime
        """
        return dt + timedelta(seconds=seconds)
    
    @staticmethod
    def subtract_seconds(dt: datetime, seconds: Union[int, float]) -> datetime:
        """
        Subtract seconds from datetime.
        
        Args:
            dt: Datetime object
            seconds: Seconds to subtract
            
        Returns:
            New datetime
        """
        return dt - timedelta(seconds=seconds)
    
    @staticmethod
    def seconds_between(start: datetime, end: datetime) -> float:
        """
        Calculate seconds between two datetimes.
        
        Args:
            start: Start datetime
            end: End datetime
            
        Returns:
            Seconds between datetimes
        """
        return (end - start).total_seconds()
    
    @staticmethod
    def is_within_window(
        dt: datetime,
        window_start: datetime,
        window_end: datetime
    ) -> bool:
        """
        Check if datetime is within time window.
        
        Args:
            dt: Datetime to check
            window_start: Window start
            window_end: Window end
            
        Returns:
            True if within window
        """
        return window_start <= dt <= window_end
    
    @staticmethod
    def get_time_buckets(
        start: datetime,
        end: datetime,
        bucket_size: int = 3600
    ) -> list:
        """
        Get time buckets between start and end.
        
        Args:
            start: Start datetime
            end: End datetime
            bucket_size: Bucket size in seconds
            
        Returns:
            List of (bucket_start, bucket_end) tuples
        """
        buckets = []
        current = start
        while current < end:
            bucket_end = min(current + timedelta(seconds=bucket_size), end)
            buckets.append((current, bucket_end))
            current = bucket_end
        return buckets
    
    @staticmethod
    def truncate_to_minute(dt: datetime) -> datetime:
        """Truncate datetime to minute precision."""
        return dt.replace(second=0, microsecond=0)
    
    @staticmethod
    def truncate_to_hour(dt: datetime) -> datetime:
        """Truncate datetime to hour precision."""
        return dt.replace(minute=0, second=0, microsecond=0)
    
    @staticmethod
    def truncate_to_day(dt: datetime) -> datetime:
        """Truncate datetime to day precision."""
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)