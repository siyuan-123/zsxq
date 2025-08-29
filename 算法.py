import hashlib
import json
import random
import time
import uuid
from urllib.parse import quote


class HTTPHeaderGenerator:
    """HTTP头参数生成器"""
    
    def __init__(self):
        """初始化生成器"""
        self.x_aduid = self._get_or_create_aduid()
    
    def _generate_uuid(self):
        """
        生成UUID 
        result = ""
        for i in range(32):
            # 生成0-15的随机数，转换为十六进制字符
            result += format(random.randint(0, 15), 'x')
            # 在特定位置插入连字符
            if i in [7, 11, 15, 19]:
                result += "-"
        return result
    
    def _get_or_create_aduid(self):
        """
        获取或创建X-Aduid（设备唯一标识符）
        
        用途：生成持久化的设备标识符，同一设备/浏览器保持不变
              
        生成逻辑：
        1. 首先尝试从localStorage读取"XAduid"
        2. 如果存在，直接返回缓存的UUID
        3. 如果不存在，调用dn()生成新UUID并存储到localStorage
        4. 特点：持久化存储，同一设备/浏览器环境下保持不变
        """
        # 模拟localStorage，使用文件存储（实际使用中可以从数据库读取）
        try:
            with open('.aduid_cache', 'r') as f:
                cached_aduid = f.read().strip()
                return cached_aduid
        except FileNotFoundError:
            # 文件不存在，生成新的Aduid并保存
            new_aduid = self._generate_uuid()
            with open('.aduid_cache', 'w') as f:
                f.write(new_aduid)
            return new_aduid
    
    def _get_timestamp(self):
        return str(int(time.time()))
    
    def _generate_signature(self, url, timestamp, request_id):
  
        # 1. URL预处理 
        processed_url = url
        if '?' in url:
            url_parts = url.split('?')
            base_url = url_parts[0] 
            query_parts = url_parts[1:]
            if query_parts:
                # 处理查询参数，将单引号编码为%27（防止注入）
                processed_url = base_url + "?" + "?".join(query_parts).replace("'", "%27")
        
        # 2. 构造签名字符串 - 格式：URL + 空格 + timestamp + 空格 + request_id
        sign_string = f"{processed_url} {timestamp} {request_id}"
        
        # 3. SHA1哈希计算 
        sha1_hash = hashlib.sha1(sign_string.encode('utf-8')).hexdigest()
        return sha1_hash
    
    def generate_headers(self, url, request_id=None, timestamp=None, aduid=None):
        """
        生成完整的HTTP头参数（支持自动生成和验证模式）
        
        功能说明：
        - 自动生成模式：不传参数，自动生成所有新参数
        - 验证模式：传入已知参数，用于验证算法正确性
        
        参数生成顺序（JavaScript中的实际调用顺序）：
        1. X-Aduid：持久化设备标识符（localStorage缓存）
        2. X-Timestamp：当前Unix时间戳（秒级）
        3. X-Request-Id：每次请求的新UUID
        4. X-Signature：基于前三者计算的SHA1签名
        
        Args:
            url (str): 请求的URL
            request_id (str, optional): 指定request_id用于验证，不传则自动生成新UUID
            timestamp (str, optional): 指定timestamp用于验证，不传则使用当前时间戳
            aduid (str, optional): 指定aduid用于验证，不传则使用缓存的设备标识符
            
        Returns:
            dict: 包含所有HTTP头参数的字典
            {
                "X-Request-Id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "X-Timestamp": "1756460115", 
                "X-Aduid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "X-Signature": "40位SHA1哈希字符串"
            }
        """
        # 1. X-Request-Id：每次请求的唯一标识符
        # 传入则使用传入值（验证模式），否则生成新的UUID（自动生成模式）
        if request_id is None:
            request_id = self._generate_uuid()
        
        # 2. X-Timestamp：时间戳
        # 传入则使用传入值（验证模式），否则使用当前时间戳（自动生成模式）
        if timestamp is None:
            timestamp = self._get_timestamp()
        
        # 3. X-Aduid：设备唯一标识符  
        # 传入则使用传入值（验证模式），否则使用持久化的设备标识符（自动生成模式）
        if aduid is None:
            aduid = self.x_aduid
        
        # 4. X-Signature：完整性验证签名
        # 始终基于URL、时间戳和请求ID重新计算（确保一致性）
        signature = self._generate_signature(url, timestamp, request_id)
        
        return {
            "X-Request-Id": request_id,
            "X-Timestamp": timestamp,
            "X-Aduid": aduid,
            "X-Signature": signature
        }
    
    def verify_signature(self, url, expected_signature, timestamp, request_id):
        """
        验证签名是否正确
        
        Args:
            url (str): 请求的URL
            expected_signature (str): 期望的签名值
            timestamp (str): 时间戳
            request_id (str): 请求ID
            
        Returns:
            dict: 验证结果信息
        """
        calculated_signature = self._generate_signature(url, timestamp, request_id)
        
        return {
            "url": url,
            "timestamp": timestamp, 
            "request_id": request_id,
            "sign_string": f"{url} {timestamp} {request_id}",
            "expected_signature": expected_signature,
            "calculated_signature": calculated_signature,
            "match": calculated_signature == expected_signature
        }
    
    def print_analysis(self, url):
        """打印详细的生成过程分析"""
        print("=" * 60)
        print("HTTP头参数生成过程分析")
        print("=" * 60)
        
        headers = self.generate_headers(url)
        
        print(f"目标URL: {url}")
        print(f"当前时间戳: {headers['X-Timestamp']}")
        print()
        
        print("1. X-Aduid 生成:")
        print(f"   - 从缓存获取或生成新的UUID")
        print(f"   - 值: {headers['X-Aduid']}")
        print()
        
        print("2. X-Request-Id 生成:")
        print(f"   - 每次请求生成新的UUID")
        print(f"   - 值: {headers['X-Request-Id']}")
        print()
        
        print("3. X-Timestamp 生成:")
        print(f"   - 当前Unix时间戳（秒）")
        print(f"   - 值: {headers['X-Timestamp']}")
        print()
        
        print("4. X-Signature 生成:")
        print(f"   - 签名字符串: {url} {headers['X-Timestamp']} {headers['X-Request-Id']}")
        print(f"   - SHA1哈希: {headers['X-Signature']}")
        print()
        
        print("最终HTTP头参数:")
        for key, value in headers.items():
            print(f"   {key}: {value}")
        
        return headers


def main():
    """主函数 - 演示算法使用和验证"""
    generator = HTTPHeaderGenerator()
    
    print("=" * 70)
    print("HTTP头参数生成器 - 支持生成和验证")
    print("=" * 70)
    
    # 1. 自动生成示例
    print("1. 自动生成HTTP头参数:")
    print("-" * 30)
    test_url = "https://api.zsxq.com/v2/groups/182428822/topics"
    headers = generator.generate_headers(test_url)
    
    print(f"URL: {test_url}")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()
    
