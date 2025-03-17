import magic
import os

def get_file_header(file_path, num_bytes=16):
    """读取文件前 num_bytes 个字节并返回十六进制字符串"""
    with open(file_path, 'rb') as f:
        header = f.read(num_bytes)
    return header.hex().upper()

def get_mime_type(file_path):
    """使用 python-magic 获取文件的 MIME 类型"""
    mime = magic.Magic(mime=True)
    return mime.from_file(file_path)

# 替换为您的文件路径
file_path = r'C:\file\lab\5a769dd650897e7a54aaa1a41f9ddfd0_1'

# 获取文件头和 MIME 类型
header = get_file_header(file_path)
mime_type = get_mime_type(file_path)

# 输出结果
print(f"文件头: {header}")
print(f"MIME 类型: {mime_type}")
