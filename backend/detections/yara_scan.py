"""
YARA scanning engine for SENTRIX LIVE++.
Scans files against YARA rules to detect malicious content.
"""
import os
import logging
import yara
from typing import Dict, List, Optional, Union
from datetime import datetime
import hashlib
import minio

from backend.core.config import settings

logger = logging.getLogger(__name__)

class YaraScanner:
    """YARA scanning engine for malware detection."""
    
    def __init__(self, rules_directory: str = None):
        """Initialize the YARA scanner with rules."""
        self.rules_directory = rules_directory or os.path.join(os.getcwd(), "rules", "yara")
        self.rules = None
        self.minio_client = minio.Minio(
            settings.minio.MINIO_ENDPOINT,
            access_key=settings.minio.MINIO_ACCESS_KEY,
            secret_key=settings.minio.MINIO_SECRET_KEY,
            secure=settings.minio.MINIO_SECURE
        )
        self.load_rules()
    
    def load_rules(self) -> None:
        """Load YARA rules from the rules directory."""
        if not os.path.exists(self.rules_directory):
            logger.warning(f"YARA rules directory not found: {self.rules_directory}")
            return
        
        try:
            # Compile all rules in the directory
            filepaths = {}
            for root, _, files in os.walk(self.rules_directory):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_path = os.path.join(root, file)
                        namespace = os.path.splitext(file)[0]
                        filepaths[namespace] = rule_path
            
            if filepaths:
                self.rules = yara.compile(filepaths=filepaths)
                logger.info(f"Loaded YARA rules from {len(filepaths)} files")
            else:
                logger.warning("No YARA rules found")
        
        except Exception as e:
            logger.error(f"Error loading YARA rules: {str(e)}")
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a file with YARA rules.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of matches with rule information
        """
        if not self.rules:
            logger.error("No YARA rules loaded")
            return []
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []
        
        try:
            # Scan the file
            matches = self.rules.match(file_path)
            
            # Process matches
            results = []
            if matches:
                file_hash = self._calculate_file_hash(file_path)
                file_size = os.path.getsize(file_path)
                
                for match in matches:
                    result = {
                        "rule_name": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [{"name": s[1], "offset": s[0], "data": s[2].hex()} for s in match.strings],
                        "file_path": file_path,
                        "file_hash": file_hash,
                        "file_size": file_size,
                        "scan_time": datetime.utcnow().isoformat()
                    }
                    results.append(result)
                    
                    logger.info(f"YARA match: {match.rule} in {file_path}")
            
            return results
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return []
    
    def scan_data(self, data: bytes, filename: str = "memory_scan") -> List[Dict]:
        """
        Scan in-memory data with YARA rules.
        
        Args:
            data: Bytes to scan
            filename: Name to use for reporting
            
        Returns:
            List of matches with rule information
        """
        if not self.rules:
            logger.error("No YARA rules loaded")
            return []
        
        try:
            # Scan the data
            matches = self.rules.match(data=data)
            
            # Process matches
            results = []
            if matches:
                data_hash = hashlib.sha256(data).hexdigest()
                data_size = len(data)
                
                for match in matches:
                    result = {
                        "rule_name": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [{"name": s[1], "offset": s[0], "data": s[2].hex()} for s in match.strings],
                        "file_name": filename,
                        "data_hash": data_hash,
                        "data_size": data_size,
                        "scan_time": datetime.utcnow().isoformat()
                    }
                    results.append(result)
                    
                    logger.info(f"YARA match: {match.rule} in memory data ({filename})")
            
            return results
        
        except Exception as e:
            logger.error(f"Error scanning data: {str(e)}")
            return []
    
    def scan_minio_object(self, bucket_name: str, object_name: str) -> List[Dict]:
        """
        Scan an object in MinIO with YARA rules.
        
        Args:
            bucket_name: MinIO bucket name
            object_name: Object name in the bucket
            
        Returns:
            List of matches with rule information
        """
        if not self.rules:
            logger.error("No YARA rules loaded")
            return []
        
        try:
            # Check if bucket exists
            if not self.minio_client.bucket_exists(bucket_name):
                logger.error(f"Bucket not found: {bucket_name}")
                return []
            
            # Get object data
            response = self.minio_client.get_object(bucket_name, object_name)
            data = response.read()
            response.close()
            
            # Scan the data
            matches = self.rules.match(data=data)
            
            # Process matches
            results = []
            if matches:
                data_hash = hashlib.sha256(data).hexdigest()
                data_size = len(data)
                
                for match in matches:
                    result = {
                        "rule_name": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": [{"name": s[1], "offset": s[0], "data": s[2].hex()} for s in match.strings],
                        "bucket_name": bucket_name,
                        "object_name": object_name,
                        "data_hash": data_hash,
                        "data_size": data_size,
                        "scan_time": datetime.utcnow().isoformat()
                    }
                    results.append(result)
                    
                    logger.info(f"YARA match: {match.rule} in {bucket_name}/{object_name}")
            
            return results
        
        except Exception as e:
            logger.error(f"Error scanning MinIO object {bucket_name}/{object_name}: {str(e)}")
            return []
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


# Singleton instance
yara_scanner = YaraScanner()


def get_yara_scanner() -> YaraScanner:
    """Get the YARA scanner instance."""
    return yara_scanner