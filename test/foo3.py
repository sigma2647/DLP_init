import os
import magic
import binascii

def check_file_signature(file_path):
    """检查文件签名和类型"""
    print(f"文件路径: {file_path}")
    print(f"文件大小: {os.path.getsize(file_path)} 字节")
    
    # 使用python-magic检测文件类型
    try:
        # 首先尝试使用libmagic的python绑定
        file_type = magic.from_file(file_path)
        mime_type = magic.from_file(file_path, mime=True)
        print(f"\nPython-magic检测结果:")
        print(f"文件类型: {file_type}")
        print(f"MIME类型: {mime_type}")
    except ImportError:
        print("未安装python-magic库，请运行 pip install python-magic 安装")
    except Exception as e:
        print(f"Magic检测出错: {str(e)}")
    
    # 直接读取文件头部字节
    try:
        with open(file_path, 'rb') as f:
            # 读取前16个字节，通常足够识别大多数文件格式
            header = f.read(16)
        
        # 将字节转换为十六进制表示
        hex_header = binascii.hexlify(header).decode('ascii')
        print(f"\n文件头十六进制: {hex_header}")
        
        # 解析常见的文件签名
        file_signatures = {
            "504B0304": "ZIP/DOCX/XLSX/PPTX",
            "D0CF11E0A1B11AE1": "MS Office文档(DOC/XLS/PPT)",
            "25504446": "PDF文件",
            "FFD8FF": "JPEG图片",
            "89504E47": "PNG图片",
            "47494638": "GIF图片",
            "377ABCAF": "7Z压缩文件",
            "1F8B08": "GZIP压缩文件",
            "526172211A07": "RAR压缩文件",
            "4D546864": "MIDI文件",
            "FD377A585A": "XZ压缩文件"
        }
        
        detected_format = "未知格式"
        for signature, format_name in file_signatures.items():
            if hex_header.lower().startswith(signature.lower()):
                detected_format = format_name
                break
        
        print(f"基于文件头的文件类型: {detected_format}")
        
        # 显示文件头的ASCII表示（仅显示可打印字符）
        ascii_header = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header)
        print(f"文件头ASCII表示: {ascii_header}")
        
    except Exception as e:
        print(f"读取文件头出错: {str(e)}")

if __name__ == "__main__":
    file_path = r"C:\file\foooooo\d22235d6a6438c395531104ef96f590d_1"
    check_file_signature(file_path)
