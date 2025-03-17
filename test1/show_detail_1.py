import olefile
import magic
from pathlib import Path

def get_file_header(file_path, num_bytes=16):
    """读取文件前 num_bytes 个字节并返回十六进制字符串"""
    with open(file_path, 'rb') as f:
        header = f.read(num_bytes)
    return header.hex().upper()

def get_mime_type(file_path):
    """使用 python-magic 获取文件的 MIME 类型"""
    mime = magic.Magic(mime=True)
    return mime.from_file(file_path)

def analyze_ole_streams(file_path):
    """分析 OLE 文件的内部流"""
    try:
        if not olefile.isOleFile(file_path):
            return "不是有效的 OLE 文件"
        
        ole = olefile.OleFileIO(file_path)
        streams = ole.listdir()
        ole.close()
        
        # 检查常见的流名称
        is_doc = any(stream[0] == 'WordDocument' for stream in streams)
        is_xls = any(stream[0] == 'Workbook' for stream in streams)
        
        result = {
            "streams": streams,
            "is_doc": is_doc,
            "is_xls": is_xls
        }
        return result
    except Exception as e:
        return f"分析 OLE 文件失败: {str(e)}"

# 替换为您的文件路径
# file_path = '72981539429c388ab24dff97838fdbf8_1.doc'
file_path = r'C:\file\wrong\72981539429c388ab24dff97838fdbf8_1'

# 获取文件头和 MIME 类型
header = get_file_header(file_path)
mime_type = get_mime_type(file_path)

# 分析 OLE 流
ole_info = analyze_ole_streams(file_path)

# 输出结果
print(f"文件路径: {file_path}")
print(f"文件头: {header}")
print(f"MIME 类型: {mime_type}")
print(f"OLE 流信息: {ole_info}")
