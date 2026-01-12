from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.exceptions import ValidationError
import hashlib
import secrets

class CustomUser(AbstractUser):
    """Enhanced user model with email and phone verification"""
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(max_length=15, unique=True)
    is_verified = models.BooleanField(default=False)
    dob = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['mobile_number']),
            models.Index(fields=['is_verified']),
        ]

class OTPAuditLog(models.Model):
    """Audit log for all OTP operations"""
    ATTEMPT_TYPES = [
        ('GENERATE', 'OTP Generated'),
        ('VERIFY_SUCCESS', 'OTP Verified Successfully'),
        ('VERIFY_FAILED', 'OTP Verification Failed'),
        ('RATE_LIMIT_HIT', 'Rate Limit Exceeded'),
        ('EXPIRED', 'OTP Expired'),
    ]
    
    mobile_number = models.CharField(max_length=15, db_index=True)
    email = models.EmailField(null=True, blank=True)
    attempt_type = models.CharField(max_length=20, choices=ATTEMPT_TYPES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(null=True, blank=True)
    success = models.BooleanField(default=False)
    reason = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['mobile_number', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
        ]
        ordering = ['-created_at']

class OTP(models.Model):
    """Secure OTP with hashing, rate limiting, and audit trail"""
    CONTEXT_CHOICES = [
        ('REGISTRATION', 'User Registration'),
        ('LOGIN', 'User Login'),
        ('PASSWORD_RESET', 'Password Reset'),
    ]
    
    mobile_number = models.CharField(max_length=15, db_index=True)
    email = models.EmailField(null=True, blank=True)
    code_hash = models.CharField(max_length=255)  # Hashed, never plaintext
    context = models.CharField(max_length=20, choices=CONTEXT_CHOICES, default='REGISTRATION')
    
    attempt_count = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=5)
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['mobile_number', '-created_at']),
            models.Index(fields=['expires_at']),
        ]
    
    @staticmethod
    def hash_otp(otp_code: str) -> str:
        """Hash OTP with SECRET_KEY salt"""
        from django.conf import settings
        salt = settings.SECRET_KEY[:16]
        return hashlib.sha256(f"{otp_code}{salt}".encode()).hexdigest()
    
    def verify_code(self, otp_code: str) -> bool:
        """Constant-time OTP comparison"""
        from secrets import compare_digest
        
        if timezone.now() > self.expires_at or self.is_verified or self.attempt_count >= self.max_attempts:
            return False
        
        return compare_digest(self.hash_otp(otp_code), self.code_hash)
    
    def mark_verified(self):
        self.is_verified = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_verified', 'verified_at'])
    
    def increment_attempt(self):
        self.attempt_count += 1
        self.last_attempt_at = timezone.now()
        self.save(update_fields=['attempt_count', 'last_attempt_at'])
    
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at
    
    def is_maxed_out(self) -> bool:
        return self.attempt_count >= self.max_attempts

class RateLimitLog(models.Model):
    """Track rate limit violations per mobile/IP"""
    mobile_number = models.CharField(max_length=15, db_index=True, unique=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    
    otp_generation_attempts = models.IntegerField(default=0)
    otp_verification_failures = models.IntegerField(default=0)
    
    is_locked = models.BooleanField(default=False)
    locked_until = models.DateTimeField(null=True, blank=True)
    lock_reason = models.CharField(max_length=255, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_attempt_at = models.DateTimeField(auto_now=True, db_index=True)
    
    def is_account_locked(self) -> bool:
        if not self.is_locked:
            return False
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        self.is_locked = False
        self.save()
        return False
