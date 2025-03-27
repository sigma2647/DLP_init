#!/usr/bin/env python3
"""
文件签名检测器 - 通过文件头部的二进制签名(magic numbers)识别文件类型
支持检测单个文件或整个目录下的所有文件
特别优化了对Office文档、PNG图像和视频文件的识别
支持多线程处理和结果缓存
"""

import os
import sys
import binascii
import argparse
import csv
import json
import struct
import tempfile
import shutil
import logging
import hashlib
import concurrent.futures
from collections import OrderedDict, Counter, defaultdict
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Optional, Tuple, Union, Any

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('file_detector.log', 'w', 'utf-8')
    ]
)
logger = logging.getLogger('FileSignatureDetector')

class FileSignatureDetector:
    def __init__(self, detector, is_windows: bool = True, verbose=False, cache_size=1024, max_workers=None):
        """
        初始化文件签名检测器，使用python-magic和基于特征的文件类型识别
        
        Args:
            detector: 父类探测器的引用
            is_windows (bool): 是否为Windows平台
            verbose (bool): 是否显示详细日志
            cache_size (int): 缓存最近处理的文件数量
            max_workers (int): 多线程处理的最大线程数，默认为CPU核心数
        """
        self.verbose = verbose
        self.max_workers = max_workers or (os.cpu_count() or 1) * 2
        self.is_windows = is_windows
        self.detector = detector
        
        # 设置日志级别
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # 初始化python-magic
        try:
            self.mime = magic.Magic(mime=True)
            logger.info("初始化magic库用于MIME类型检测")
        except ImportError:
            logger.warning("未安装python-magic库，部分文件检测功能将受限")
            self.mime = None
        except Exception as e:
            logger.error(f"初始化magic库出错: {e}")
            self.mime = None
        
        # 反向映射
        self.MIME_TO_EXT = {mime: ext for ext, mime in self.MIME_TYPES.items()}
        
        # 编译正则表达式以提高性能
        self.ole_pattern = re.compile(r'(WordDocument|Workbook|PowerPoint Document|Microsoft (?:Word|Excel|PowerPoint))', re.IGNORECASE)
        self.excel_cell_pattern = re.compile(r'Cell[^a-zA-Z0-9]', re.IGNORECASE)
        self.excel_sheet_pattern = re.compile(r'Sheet\d', re.IGNORECASE)
        self.internal_stream_pattern = re.compile(r'^\[\d+\].+|^~\$|^__SRP_\d+$|^__substg1\.0_|^__attach_version1\.0_|^__properties_version1\.0$|^MsoDataStore|Thumbs\.db$|\.tmp$')
        
        # 文件签名字典（十六进制 -> 文件类型）
        self.signatures = OrderedDict([
            # 办公文档格式
            (b'504B0304', 'ZIP格式 (可能是Office文档/APK/JAR等)'),
            (b'D0CF11E0A1B11AE1', 'Microsoft复合文档二进制格式 (DOC/XLS/PPT等)'),
            
            # 图像文件格式 - 增强PNG识别
            (b'FFD8FF', 'JPEG图像'),
            (b'89504E470D0A1A0A', 'PNG图像'),  # 后续会通过_analyze_png_structure进一步分析
            (b'47494638', 'GIF图像'),
            (b'424D', 'BMP图像'),
            (b'49492A00', 'TIFF图像 (小端)'),
            (b'4D4D002A', 'TIFF图像 (大端)'),
            (b'52494646', 'WEBP/WAV/AVI (RIFF格式)'),
            (b'38425053', 'Photoshop文档 (PSD)'),
            
            # 音视频文件格式 - 增强视频识别
            (b'494433', 'MP3音频 (ID3标签)'),
            (b'FFFB', 'MP3音频'),
            (b'FFF3', 'MP3音频'),
            (b'FFF2', 'MP3音频'),
            (b'664C6143', 'FLAC音频'),
            (b'52494646', 'WAV音频 (RIFF标记)'),
            (b'4F676753', 'OGG音频/视频'),
            (b'1A45DFA3', 'Matroska视频 (MKV)'),
            (b'000001BA', 'MPEG传输流 (TS/MTS)'),
            (b'000001B3', 'MPEG视频 (MPG/MPEG)'),
            (b'6674797069736F6D', 'MP4视频'),
            (b'4654595049534F4D', 'MP4视频'),
            (b'52494646', 'AVI视频 (RIFF标记)'),
            (b'3026B2758E66CF11', 'ASF/WMV/WMA'),
            (b'464C5601', 'FLV视频'),
            (b'55525330', 'Video URT'),
            (b'00000020667479706D70', 'MP4视频 (高级格式)'),
            (b'667479704D344120', 'M4A音频容器'),
            (b'2E524D46', 'RealMedia文件'),
            (b'2E524D5600000012', 'RealVideo文件'),
            (b'2E4B4445', 'KDE分区表'),
            
            # 压缩和存档格式
            (b'504B0304', 'ZIP压缩包'),
            (b'526172211A0700', 'RAR压缩包 (v1.5+)'),
            (b'526172211A070100', 'RAR压缩包 (v5.0+)'),
            (b'377ABCAF271C', 'RAR压缩包 (旧版本)'),
            (b'1F8B08', 'GZIP压缩包'),
            (b'1F9D', 'COMPRESS压缩数据'),
            (b'425A68', 'BZIP2压缩包'),
            (b'FD377A585A00', 'XZ压缩包'),
            (b'04224D18', '7-ZIP压缩包'),
            (b'213C617263683E0A', 'DEB安装包'),
            
            # 可执行文件和二进制格式
            (b'4D5A', 'Windows可执行文件 (EXE/DLL/OCX)'),
            (b'7F454C46', 'ELF可执行文件 (Linux/Unix)'),
            (b'CAFEBABE', 'Java类文件/Mach-O Fat文件'),
            (b'FEEDFACE', 'Mach-O (32位)'),
            (b'FEEDFACF', 'Mach-O (64位)'),
            (b'CEFAEDFE', 'Mach-O (逆序, 32位)'),
            (b'CFFAEDFE', 'Mach-O (逆序, 64位)'),
            (b'DEY\x01', 'DEX (Dalvik可执行文件, Android)'),
            (b'FEEDFEED', 'JKS Java密钥存储'),
            
            # 数据库和索引格式
            (b'53514C69746520666F726D6174203300', 'SQLite数据库'),
            (b'4D7953514C', 'MySQL数据库'),
            (b'1F8B08', 'GZ数据库备份'),
            (b'5249464644', 'Webm格式'),
            
            # 文档和富文本格式
            (b'25504446', 'PDF文档'),
            (b'7B5C72746631', 'RTF文档'),
            (b'0A2524454E44', 'UNIX mailbox'),
            
            # 字体格式
            (b'4F54544F', 'OpenType字体'),
            (b'00010000', 'TrueType字体'),
            (b'774F4646', 'WOFF字体'),
            (b'774F4632', 'WOFF2字体'),
            
            # 系统和容器格式
            (b'4C000000011402', 'Windows链接文件 (LNK)'),
            (b'49536328', 'Windows安装程序包 (CAB)'),
            (b'0000000C6A502020', 'JPEG2000图像'),
            (b'EDABEEDB', 'RPM包管理器包'),
            (b'53494D504C4520', 'FITS科学图像格式'),
            (b'414331303031', 'GPG/PGP加密文件'),
            
            # 开发相关格式
            (b'3C3F786D6C', 'XML文件'),
            (b'3C68746D6C', 'HTML文件'),
            (b'3C21444F43', 'HTML文件 (带DOCTYPE)'),
            (b'255044462D', 'PDF文档 (带版本)'),
            (b'2321', 'Shell脚本'),
            (b'7061636B', 'Python已编译代码'),
            (b'4C01', 'ELF文件对象'),
            
            # 文本编码标记
            (b'EFBBBF', 'UTF-8带BOM文本'),
            (b'FEFF', 'UTF-16 (BE)带BOM文本'),
            (b'FFFE', 'UTF-16 (LE)带BOM文本'),
            (b'FFFE0000', 'UTF-32 (LE)带BOM文本'),
            (b'0000FEFF', 'UTF-32 (BE)带BOM文本'),
            
            # 虚拟机和容器格式
            (b'4B444D', 'VMDK虚拟机磁盘'),
            (b'7F454C46', 'ELF可执行文件'),
            (b'23204469736B2044', 'VDI虚拟机磁盘'),
            (b'636F6E6563746978', 'VHD虚拟机磁盘'),
            (b'213C617263683E', 'Linux ar归档'),
            (b'52656365697665', 'BitTorrent部分下载'),
        ])
        
        # 使用LRU缓存装饰器缓存文件检测结果
        self._detect = lru_cache(maxsize=cache_size)(self._detect_impl)
        
        # 文件类型统计
        self.stats = defaultdict(int)
        
        # 创建文件扩展名到MIME类型的映射
        self._init_extension_mapping()
        
        # 文件签名缓存
        self.signature_cache = {}

    def _init_extension_mapping(self):
        """初始化文件扩展名到MIME类型的映射"""
        self.extension_to_mime = {
            # 文本和文档
            '.txt': 'text/plain',
            '.html': 'text/html',
            '.htm': 'text/html',
            '.css': 'text/css',
            '.csv': 'text/csv',
            '.xml': 'text/xml',
            '.json': 'application/json',
            '.js': 'application/javascript',
            '.md': 'text/markdown',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.rtf': 'application/rtf',
            '.odt': 'application/vnd.oasis.opendocument.text',
            
            # 图片
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.tiff': 'image/tiff',
            '.tif': 'image/tiff',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            
            # 视频
            '.mp4': 'video/mp4',
            '.m4v': 'video/mp4',
            '.mkv': 'video/x-matroska',
            '.webm': 'video/webm',
            '.avi': 'video/x-msvideo',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.mpg': 'video/mpeg',
            '.mpeg': 'video/mpeg',
            '.flv': 'video/x-flv',
            
            # 音频
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.aac': 'audio/aac',
            '.ogg': 'audio/ogg',
            '.flac': 'audio/flac',
            '.m4a': 'audio/mp4',
            '.wma': 'audio/x-ms-wma',
            
            # 压缩包
            '.zip': 'application/zip',
            '.rar': 'application/vnd.rar',
            '.7z': 'application/x-7z-compressed',
            '.tar': 'application/x-tar',
            '.gz': 'application/gzip',
            '.bz2': 'application/x-bzip2',
            
            # 电子表格和演示文稿
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
            '.odp': 'application/vnd.oasis.opendocument.presentation',
            
            # 其他
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.so': 'application/octet-stream',
            '.iso': 'application/x-iso9660-image',
            '.apk': 'application/vnd.android.package-archive',
            '.ttf': 'font/ttf',
            '.otf': 'font/otf',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
        }

    @lru_cache(maxsize=128)
    def _read_file_header(self, file_path, bytes_count=32):
        """
        读取文件头部字节
        
        Args:
            file_path (str): 文件路径
            bytes_count (int): 要读取的字节数
            
        Returns:
            bytes: 文件头部字节，如果读取失败则返回None
        """
        try:
            with open(file_path, 'rb') as file:
                header = file.read(bytes_count)
            return header
        except Exception as e:
            if self.verbose:
                logger.error(f"无法读取文件 {file_path}: {e}")
            return None

    def _check_office_signatures(self, file_path):
        """
        专门检查Office文档签名，包括处理签名损坏的情况
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            str: 识别的Office文档类型，如果不是Office文档则返回None
        """
        try:
            # 首先检查文件大小，Office文档通常不会太小
            file_size = os.path.getsize(file_path)
            if file_size < 4096:  # 小于4KB可能不是Office文档
                return None
                
            # 读取文件头部
            header = self._read_file_header(file_path, 16)
            if not header:
                return None
                
            header_hex = binascii.hexlify(header).upper()
                
            # 首先检查标准签名
            if header_hex.startswith(b'D0CF11E0A1B11AE1'):
                # 这是Office二进制格式，进一步判断具体类型
                return self._analyze_ole_file(file_path)
                
            if header_hex.startswith(b'504B0304'):
                # 这可能是Office Open XML格式，进一步判断
                return self._analyze_ooxml_file(file_path)
                
            # 检查签名损坏的情况
            # 有时文件头部可能被损坏，但仍然保留了部分Office格式的特征
            
            # 创建临时文件副本进行修复尝试
            temp_dir = tempfile.mkdtemp()
            try:
                temp_file = os.path.join(temp_dir, "temp_file")
                shutil.copy2(file_path, temp_file)
                
                # 尝试修复OLE结构标记
                if self._try_repair_ole(temp_file):
                    result = self._analyze_ole_file(temp_file)
                    if result:
                        return f"{result} (已修复签名)"
                
                # 尝试修复ZIP/OOXML结构
                if self._try_repair_ooxml(temp_file):
                    result = self._analyze_ooxml_file(temp_file)
                    if result:
                        return f"{result} (已修复签名)"
                
            finally:
                # 清理临时文件
                shutil.rmtree(temp_dir, ignore_errors=True)
                
            # 如果没有明确匹配，尝试基于内容特征判断
            return self._guess_office_type_by_content(file_path)
            
        except Exception as e:
            if self.verbose:
                logger.error(f"分析Office文档签名时出错: {e}")
            return None
    
    def _try_repair_ole(self, file_path):
        """
        尝试修复OLE格式的签名
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            bool: 修复是否成功
        """
        try:
            with open(file_path, 'r+b') as f:
                # OLE头部标记是 D0CF11E0A1B11AE1
                ole_signature = bytearray([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
                f.seek(0)
                f.write(ole_signature)
                return True
        except:
            return False
    
    def _try_repair_ooxml(self, file_path):
        """
        尝试修复OOXML(ZIP)格式的签名
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            bool: 修复是否成功
        """
        try:
            with open(file_path, 'r+b') as f:
                # ZIP/OOXML头部标记是 504B0304
                zip_signature = bytearray([0x50, 0x4B, 0x03, 0x04])
                f.seek(0)
                f.write(zip_signature)
                return True
        except:
            return False
            
    def _analyze_ole_file(self, file_path):
        """
        深度分析OLE文件结构来确定具体的Office文件类型
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            str: 识别的Office文档类型
        """
        try:
            # 读取更多文件内容以便深度分析
            with open(file_path, 'rb') as f:
                content = f.read(32768)  # 读取前32KB内容进行分析
                
            # 特定二进制标记检测
            # 检查是否存在Word特有的二进制指纹
            word_markers = [
                b'\x57\x00\x6F\x00\x72\x00\x64\x00\x44\x00\x6F\x00\x63\x00',  # "WordDoc" in UTF-16
                b'\x57\x00\x6F\x00\x72\x00\x64\x00\x2E\x00\x44\x00\x6F\x00\x63\x00',  # "Word.Doc" in UTF-16
                b'\x4D\x53\x57\x6F\x72\x64\x44\x6F\x63',  # "MSWordDoc"
                b'\x42\x6A\x44\x77\x70'  # "BjDwp" 特有标记
            ]
            
            # 检查是否存在Excel特有的二进制指纹
            excel_markers = [
                b'\x57\x00\x6F\x00\x72\x00\x6B\x00\x62\x00\x6F\x00\x6F\x00\x6B\x00',  # "Workbook" in UTF-16
                b'\x45\x00\x78\x00\x63\x00\x65\x00\x6C\x00',  # "Excel" in UTF-16
                b'\x42\x00\x49\x00\x46\x00\x46',  # "BIFF" in UTF-16
                b'\x53\x68\x65\x65\x74',  # "Sheet"
                b'\xE5\x7A\x31\x1C'  # Excel 特有二进制标记
            ]
            
            # 检查是否存在PowerPoint特有的二进制指纹
            ppt_markers = [
                b'\x50\x00\x6F\x00\x77\x00\x65\x00\x72\x00\x50\x00\x6F\x00\x69\x00\x6E\x00\x74\x00',  # "PowerPoint" in UTF-16
                b'\x50\x52\x45\x53\x45\x4E\x54\x41\x54\x49\x4F\x4E',  # "PRESENTATION"
                b'\x50\x50\x30\x31',  # PPT 特有标记
                b'\x53\x6C\x69\x64\x65'  # "Slide"
            ]
            
            # 计算匹配的标记数量
            word_matches = sum(1 for marker in word_markers if marker in content)
            excel_matches = sum(1 for marker in excel_markers if marker in content)
            ppt_matches = sum(1 for marker in ppt_markers if marker in content)
            
            # 分析文件结构中的目录名称
            # Office文档通常有特定的流和存储名称
            ole_dirs = []
            pos = 0
            while True:
                pos = content.find(b'\x03\x00', pos)
                if pos == -1 or pos + 64 > len(content):
                    break
                    
                # 尝试提取目录名称 (通常是UTF-16编码)
                dir_name_bytes = content[pos+2:pos+64]
                try:
                    dir_name = dir_name_bytes.decode('utf-16-le').strip('\x00')
                    if dir_name and len(dir_name) > 1:
                        ole_dirs.append(dir_name)
                except:
                    pass
                pos += 1
            
            # 检查特定的目录名称
            word_dirs = ['WordDocument', 'Document', '1Table', 'Data', 'ObjectPool']
            excel_dirs = ['Workbook', 'Book', 'SummaryInformation', 'Worksheet']
            ppt_dirs = ['PowerPoint Document', 'Pictures', 'Current User', 'SummaryInformation']
            
            word_dir_matches = sum(1 for d in word_dirs if d in ole_dirs)
            excel_dir_matches = sum(1 for d in excel_dirs if d in ole_dirs)
            ppt_dir_matches = sum(1 for d in ppt_dirs if d in ole_dirs)
            
            # 扫描特定的十六进制模式
            # Word .doc 文件中的特定16进制模式
            if b'\xEC\xA5\xC1\x00' in content or b'\x42\x6F\x6F\x6B\x6D\x61\x72\x6B' in content:
                word_matches += 2
                
            # Excel .xls 文件中的特定16进制模式
            if b'\x09\x08\x10\x00\x00\x06\x05\x00' in content or b'\xFD\xFF\xFF\xFF\x10' in content:
                excel_matches += 2
                
            # PowerPoint .ppt 文件中的特定16进制模式
            if b'\xA0\x46\x1D\xF0' in content or b'\x00\x6E\x28\x00' in content:
                ppt_matches += 2
                
            # 分析文档头部的魔数特征
            # 读取文件的特定偏移位置
            try:
                with open(file_path, 'rb') as f:
                    f.seek(512)  # 跳过OLE头
                    sector_data = f.read(128)
                    
                    # Excel特有的扇区标记
                    if sector_data.startswith(b'\x09\x08') or b'\xFD\xFF\x00\x00' in sector_data:
                        excel_matches += 3
                        
                    # Word特有的扇区标记
                    if b'\xEC\xA5\xC1\x00' in sector_data or sector_data.startswith(b'\xDC\x00'):
                        word_matches += 3
                        
                    # PowerPoint特有的扇区标记
                    if b'\x00\x6E\x28\x00' in sector_data or b'\x0F\x00\x00\x00\xAF' in sector_data:
                        ppt_matches += 3
            except:
                pass
                
            # 统计字节频率分布，各种文档类型有不同的分布特征
            byte_freq = {}
            for b in content[:4096]:  # 只分析前4KB
                if b not in byte_freq:
                    byte_freq[b] = 0
                byte_freq[b] += 1
                
            # 某些字节频率是特定文档类型的指示器
            if byte_freq.get(0x57, 0) > 30 and byte_freq.get(0x6F, 0) > 30:  # 'W', 'o'
                word_matches += 1
            if byte_freq.get(0x45, 0) > 30 and byte_freq.get(0x78, 0) > 30:  # 'E', 'x'
                excel_matches += 1
            if byte_freq.get(0x50, 0) > 30 and byte_freq.get(0x53, 0) > 20:  # 'P', 'S'
                ppt_matches += 1
                
            # 综合分析结果，确定最可能的文件类型
            if self.verbose:
                logger.debug(f"Word 匹配得分: {word_matches}")
                logger.debug(f"Excel 匹配得分: {excel_matches}")
                logger.debug(f"PowerPoint 匹配得分: {ppt_matches}")
                
            # 根据匹配分数判断文件类型
            scores = {
                "Microsoft Word文档 (.doc)": word_matches,
                "Microsoft Excel工作簿 (.xls)": excel_matches,
                "Microsoft PowerPoint演示文稿 (.ppt)": ppt_matches
            }
            
            # 找出得分最高的类型
            max_score_type = max(scores.items(), key=lambda x: x[1])
            
            # 只有当得分超过阈值时才确定为该类型
            if max_score_type[1] >= 2:
                return max_score_type[0]
            elif max_score_type[1] > 0:
                return f"可能是{max_score_type[0]} (置信度低)"
            else:
                # 额外检查文件扩展名
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.doc':
                    return "Microsoft Word文档 (.doc) (基于文件扩展名)"
                elif ext == '.xls':
                    return "Microsoft Excel工作簿 (.xls) (基于文件扩展名)"
                elif ext == '.ppt':
                    return "Microsoft PowerPoint演示文稿 (.ppt) (基于文件扩展名)"
                    
                return "Microsoft Office二进制文档 (无法确定具体类型)"
                    
        except Exception as e:
            if self.verbose:
                logger.error(f"分析OLE文件时出错: {e}")
            return "Microsoft Office二进制文档 (分析出错)"

    def _analyze_png_structure(self, file_path):
        """
        深度分析PNG文件结构，获取详细信息
        
        Args:
            file_path (str): PNG文件路径
            
        Returns:
            str: 带有详细信息的PNG图像类型描述
        """
        try:
            with open(file_path, 'rb') as f:
                # 验证PNG签名
                signature = f.read(8)
                if signature != b'\x89PNG\r\n\x1a\n':
                    return "PNG图像 (签名异常)"
                    
                # 读取IHDR块
                chunk_length = struct.unpack('>I', f.read(4))[0]
                chunk_type = f.read(4)
                
                if chunk_type != b'IHDR':
                    return "PNG图像 (结构异常，缺少IHDR块)"
                    
                # 读取图像宽度和高度
                width = struct.unpack('>I', f.read(4))[0]
                height = struct.unpack('>I', f.read(4))[0]
                
                # 读取颜色深度和颜色类型
                bit_depth = struct.unpack('B', f.read(1))[0]
                color_type = struct.unpack('B', f.read(1))[0]
                compression = struct.unpack('B', f.read(1))[0]
                filter_method = struct.unpack('B', f.read(1))[0]
                interlace = struct.unpack('B', f.read(1))[0]
                
                # 跳过CRC
                f.read(4)
                
                # 判断PNG类型
                png_type = "PNG图像"
                color_info = ""
                
                # 颜色类型解释
                if color_type == 0:
                    color_info = "灰度图"
                elif color_type == 2:
                    color_info = "RGB彩色"
                elif color_type == 3:
                    color_info = "索引彩色"
                elif color_type == 4:
                    color_info = "带透明通道灰度图"
                elif color_type == 6:
                    color_info = "带透明通道RGB彩色"
                
                # 检查是否为动态PNG
                is_animated = False
                chunks = []
                
                # 读取所有块
                while True:
                    try:
                        chunk_data = f.read(8)  # 读取长度和类型
                        if not chunk_data or len(chunk_data) < 8:
                            break
                            
                        length = struct.unpack('>I', chunk_data[:4])[0]
                        c_type = chunk_data[4:8]
                        chunks.append(c_type)
                        
                        if c_type == b'acTL':  # 动画控制块
                            is_animated = True
                            # 读取帧数
                            frame_data = f.read(8)  # 读取帧数和循环次数
                            num_frames = struct.unpack('>I', frame_data[:4])[0]
                            f.seek(length - 8 + 4, 1)  # 跳过剩余数据和CRC
                        elif c_type == b'IEND':  # 文件结束
                            break
                        else:
                            # 跳过数据和CRC
                            f.seek(length + 4, 1)
                    except Exception as e:
                        if self.verbose:
                            logger.error(f"读取PNG块时出错: {e}")
                        break
                
                # 特殊类型检测
                has_transparency = b'tRNS' in chunks
                has_text = any(chunk in chunks for chunk in [b'tEXt', b'iTXt', b'zTXt'])
                
                # 生成详细描述
                details = []
                
                if is_animated:
                    details.append(f"APNG动态图像 ({num_frames}帧)")
                else:
                    details.append(png_type)
                
                details.append(f"{width}x{height}")
                details.append(f"{bit_depth}位{color_info}")
                
                if not is_animated and has_transparency:
                    details.append("带透明通道")
                
                if has_text:
                    details.append("包含文本数据")
                
                if interlace == 1:
                    details.append("交错扫描")
                
                # 检查是否为优化的PNG
                if b'IDAT' in chunks:
                    idat_count = chunks.count(b'IDAT')
                    if idat_count > 1:
                        details.append(f"包含{idat_count}个数据块")
                
                # 完整性检查
                if b'IEND' not in chunks:
                    details.append("文件不完整(缺少IEND块)")
                
                # 文件大小
                file_size = os.path.getsize(file_path)
                size_kb = file_size / 1024
                if size_kb < 1000:
                    details.append(f"{size_kb:.1f}KB")
                else:
                    details.append(f"{size_kb/1024:.2f}MB")
                
                return " - ".join(details)
                
        except Exception as e:
            if self.verbose:
                logger.error(f"分析PNG结构时出错: {e}")
            return "PNG图像 (分析出错)"

    def _analyze_video_file(self, file_path, header_hex):
        """
        深入分析视频文件，提取更多元数据
        
        Args:
            file_path (str): 视频文件路径
            header_hex (bytes): 文件头部的十六进制表示
            
        Returns:
            str: 带有详细信息的视频类型描述，如果不是视频文件则返回None
        """
        video_info = {}
        
        try:
            # 文件大小
            file_size = os.path.getsize(file_path)
            size_mb = file_size / (1024 * 1024)
            
            # MP4分析
            if header_hex.startswith(b'6674797069736F6D') or header_hex.startswith(b'4654595049534F4D') or b'66747970' in header_hex[:32]:
                # 读取ftyp后的标识
                with open(file_path, 'rb') as f:
                    # 定位到ftyp位置
                    if header_hex.startswith(b'6674797069736F6D') or header_hex.startswith(b'4654595049534F4D'):
                        f.seek(8)
                    else:
                        pos = 0
                        data = f.read(256)
                        pos = data.find(b'ftyp')
                        if pos >= 0:
                            f.seek(pos + 4)
                        else:
                            f.seek(8)  # 默认位置
                    
                    try:
                        brand = f.read(4).decode('ascii', errors='ignore').strip('\x00')
                    except:
                        brand = "未知"
                    
                    # 尝试识别编码器和其他元数据
                    f.seek(0)
                    data = f.read(32768)  # 读取更多数据寻找编码器信息
                    
                    # 视频编码检测
                    codec = "未知编码器"
                    if b'avc1' in data:
                        codec = "H.264/AVC"
                    elif b'hev1' in data or b'hevc' in data:
                        codec = "H.265/HEVC"
                    elif b'av01' in data:
                        codec = "AV1"
                    elif b'vp09' in data:
                        codec = "VP9"
                    elif b'mp4v' in data:
                        codec = "MPEG-4 Visual"
                    
                    # 尝试提取分辨率信息
                    resolution = self._extract_mp4_resolution(file_path)
                    
                    # 基于品牌判断子类型
                    if brand == 'isom':
                        subtype = "ISO基本媒体格式"
                    elif brand in ('mp41', 'mp42'):
                        subtype = "MP4 v1/v2"
                    elif brand == 'M4V ':
                        subtype = "iTunes视频"
                    elif brand == 'M4A ':
                        subtype = "iTunes音频"
                    elif brand == 'qt  ':
                        subtype = "QuickTime"
                    else:
                        subtype = f"子类型: {brand}"
                    
                    # 构建详细信息
                    details = [f"MP4视频 ({subtype})"]
                    
                    if resolution:
                        details.append(resolution)
                    
                    details.append(f"{codec}编码")
                    details.append(f"{size_mb:.2f}MB")
                    
                    return " - ".join(details)
                    
            # MKV/WebM分析
            elif header_hex.startswith(b'1A45DFA3'):
                # 读取前64KB进行分析
                with open(file_path, 'rb') as f:
                    data = f.read(65536)
                
                # 基本类型判断
                base_type = "Matroska视频 (MKV)"
                if b'webm' in data:
                    base_type = "WebM视频"
                
                # 尝试提取更多信息
                # 简化的视频轨道和音频轨道计数
                video_streams = data.count(b'\x83\x81\x01')  # 简化的视频轨道计数方法
                audio_streams = data.count(b'\x83\x81\x02')  # 简化的音频轨道计数方法
                
                if video_streams == 0 and audio_streams > 0:
                    base_type = "Matroska音频"
                
                # 尝试提取分辨率信息
                resolution = self._extract_mkv_resolution(data)
                
                # 构建详细信息
                details = [base_type]
                
                if resolution:
                    details.append(resolution)
                
                if video_streams > 0 or audio_streams > 0:
                    stream_info = []
                    if video_streams > 0:
                        stream_info.append(f"{video_streams}个视频流")
                    if audio_streams > 0:
                        stream_info.append(f"{audio_streams}个音频流")
                    details.append(" + ".join(stream_info))
                
                details.append(f"{size_mb:.2f}MB")
                
                return " - ".join(details)
                
            # AVI分析
            elif header_hex.startswith(b'52494646') and b'AVI' in self._read_file_header(file_path, 16):
                with open(file_path, 'rb') as f:
                    data = f.read(4096)
                    
                # 尝试提取分辨率信息
                resolution = self._extract_avi_resolution(data)
                
                # 构建详细信息
                details = ["AVI视频"]
                
                if resolution:
                    details.append(resolution)
                
                # 尝试检测codec
                codec = "未知编码器"
                if b'DIVX' in data:
                    codec = "DivX"
                elif b'XVID' in data:
                    codec = "XviD"
                elif b'H264' in data or b'h264' in data:
                    codec = "H.264"
                elif b'MJPG' in data:
                    codec = "Motion JPEG"
                
                if codec != "未知编码器":
                    details.append(f"{codec}编码")
                
                details.append(f"{size_mb:.2f}MB")
                
                return " - ".join(details)
                
            # 更多视频格式可以在此添加...
            
            # FLV分析
            elif header_hex.startswith(b'464C5601'):
                # 构建详细信息
                details = ["Flash视频 (FLV)"]
                details.append(f"{size_mb:.2f}MB")
                
                return " - ".join(details)
                
            # MPEG分析
            elif header_hex.startswith(b'000001BA') or header_hex.startswith(b'000001B3'):
                if header_hex.startswith(b'000001BA'):
                    base_type = "MPEG传输流 (TS/MTS)"
                else:
                    base_type = "MPEG视频 (MPG/MPEG)"
                    
                # 构建详细信息
                details = [base_type]
                details.append(f"{size_mb:.2f}MB")
                
                return " - ".join(details)
        
        except Exception as e:
            if self.verbose:
                logger.error(f"分析视频文件时出错: {e}")
                
        # 如果详细分析失败，返回基本类型
        if header_hex.startswith(b'6674797069736F6D') or header_hex.startswith(b'4654595049534F4D') or b'66747970' in header_hex[:32]:
            return f"MP4视频 ({size_mb:.2f}MB)"
        elif header_hex.startswith(b'1A45DFA3'):
            return f"Matroska视频 (MKV) ({size_mb:.2f}MB)"
        elif header_hex.startswith(b'52494646') and b'AVI' in self._read_file_header(file_path, 16):
            return f"AVI视频 ({size_mb:.2f}MB)"
        elif header_hex.startswith(b'464C5601'):
            return f"Flash视频 (FLV) ({size_mb:.2f}MB)"
        elif header_hex.startswith(b'000001BA'):
            return f"MPEG传输流 (TS/MTS) ({size_mb:.2f}MB)"
        elif header_hex.startswith(b'000001B3'):
            return f"MPEG视频 (MPG/MPEG) ({size_mb:.2f}MB)"
            
        return None
        
    def _extract_mp4_resolution(self, file_path):
        """
        从MP4文件中提取视频分辨率
        
        Args:
            file_path (str): MP4文件路径
            
        Returns:
            str: 分辨率字符串，如果无法提取则返回None
        """
        try:
            # 这里使用一个简化的方法
            # 在实际应用中，应该使用专门的MP4解析库
            with open(file_path, 'rb') as f:
                # 搜索moov/trak/mdia/minf/stbl/stsd/avc1块
                data = f.read(1048576)  # 读取前1MB
                
                # 寻找avc1或mp4v块
                pos_avc = data.find(b'avc1')
                pos_mp4v = data.find(b'mp4v')
                
                if pos_avc > 0:
                    pos = pos_avc
                elif pos_mp4v > 0:
                    pos = pos_mp4v
                else:
                    return None
                    
                # 在编码块后面通常有分辨率信息
                # 宽度和高度通常在编码块后16-24字节处
                if pos + 28 < len(data):
                    width = struct.unpack('>H', data[pos+24:pos+26])[0]
                    height = struct.unpack('>H', data[pos+26:pos+28])[0]
                    
                    if width > 0 and height > 0 and width < 10000 and height < 10000:
                        return f"{width}x{height}"
                
            return None
        except Exception as e:
            if self.verbose:
                logger.error(f"从MP4提取分辨率时出错: {e}")
            return None
            
    def _extract_mkv_resolution(self, data):
        """
        从MKV数据中提取视频分辨率
        
        Args:
            data (bytes): MKV文件的前部数据
            
        Returns:
            str: 分辨率字符串，如果无法提取则返回None
        """
        try:
            # 这是一个简化的方法，实际应使用EBML解析库
            # 寻找像素宽度和高度标记
            # 宽度标记: 0xB0 + 数据
            # 高度标记: 0xBA + 数据
            width = None
            height = None
            
            # 查找宽度
            pos_w = data.find(b'\x89\x88\xB0')
            if pos_w > 0 and pos_w + 5 < len(data):
                try:
                    width = struct.unpack('>H', data[pos_w+3:pos_w+5])[0]
                except:
                    pass
                    
            # 查找高度
            pos_h = data.find(b'\x89\x88\xBA')
            if pos_h > 0 and pos_h + 5 < len(data):
                try:
                    height = struct.unpack('>H', data[pos_h+3:pos_h+5])[0]
                except:
                    pass
            
            if width and height and width > 0 and height > 0 and width < 10000 and height < 10000:
                return f"{width}x{height}"
                
            return None
        except Exception as e:
            if self.verbose:
                logger.error(f"从MKV提取分辨率时出错: {e}")
            return None
            
    def _extract_avi_resolution(self, data):
        """
        从AVI数据中提取视频分辨率
        
        Args:
            data (bytes): AVI文件的前部数据
            
        Returns:
            str: 分辨率字符串，如果无法提取则返回None
        """
        try:
            # 寻找strf块
            pos = data.find(b'strf')
            if pos >= 0 and pos + 20 < len(data):
                try:
                    width = struct.unpack('<I', data[pos+12:pos+16])[0]
                    height = struct.unpack('<I', data[pos+16:pos+20])[0]
                    
                    if width > 0 and height > 0 and width < 10000 and height < 10000:
                        return f"{width}x{height}"
                except:
                    pass
                    
            return None
        except Exception as e:
            if self.verbose:
                logger.error(f"从AVI提取分辨率时出错: {e}")
            return None









