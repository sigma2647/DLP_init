#!/usr/bin/env python3
"""
文件签名检测器 - 通过文件头部的二进制签名(magic numbers)识别文件类型
支持检测单个文件或整个目录下的所有文件
特别优化了对Office文档的识别，包括处理签名损坏的情况
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
from collections import OrderedDict, Counter
from datetime import datetime

class FileSignatureDetector:
    def __init__(self, verbose=False):
        """初始化文件签名探测器"""
        self.verbose = verbose
        # 文件签名字典（十六进制 -> 文件类型）
        self.signatures = OrderedDict([
            # 办公文档格式
            (b'504B0304', 'ZIP格式 (可能是Office文档/APK/JAR等)'),
            (b'D0CF11E0A1B11AE1', 'Microsoft复合文档二进制格式 (DOC/XLS/PPT等)'),
            
            # 图像文件格式
            (b'FFD8FF', 'JPEG图像'),
            (b'89504E470D0A1A0A', 'PNG图像'),
            (b'47494638', 'GIF图像'),
            (b'424D', 'BMP图像'),
            (b'49492A00', 'TIFF图像 (小端)'),
            (b'4D4D002A', 'TIFF图像 (大端)'),
            (b'52494646', 'WEBP/WAV/AVI (RIFF格式)'),
            (b'38425053', 'Photoshop文档 (PSD)'),
            
            # 音视频文件格式
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

    def _read_file_header(self, file_path, bytes_count=32):
        """读取文件头部字节"""
        try:
            with open(file_path, 'rb') as file:
                header = file.read(bytes_count)
            return header
        except Exception as e:
            if self.verbose:
                print(f"无法读取文件 {file_path}: {e}")
            return None

    def _check_office_signatures(self, file_path):
        """专门检查Office文档签名，包括处理签名损坏的情况"""
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
                print(f"分析Office文档签名时出错: {e}")
            return None
    
    def _try_repair_ole(self, file_path):
        """尝试修复OLE格式的签名"""
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
        """尝试修复OOXML(ZIP)格式的签名"""
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
        """深度分析OLE文件结构来确定具体的Office文件类型"""
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
                print(f"Word 匹配得分: {word_matches}")
                print(f"Excel 匹配得分: {excel_matches}")
                print(f"PowerPoint 匹配得分: {ppt_matches}")
                
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
                print(f"分析OLE文件时出错: {e}")
            return "Microsoft Office二进制文档 (分析出错)"
    
    def _analyze_ooxml_file(self, file_path):
        """分析OOXML (Office Open XML)文件来确定具体的Office文件类型"""
        try:
            import zipfile
            
            # 检查是否是有效的ZIP文件
            if not zipfile.is_zipfile(file_path):
                return None
                
            with zipfile.ZipFile(file_path) as zf:
                # 获取文件列表
                file_list = zf.namelist()
                
                # 检查[Content_Types].xml
                if '[Content_Types].xml' in file_list:
                    try:
                        content_types = zf.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                        
                        # 检查Word文档
                        if 'application/vnd.openxmlformats-officedocument.wordprocessingml' in content_types:
                            return "Microsoft Word文档 (.docx)"
                            
                        # 检查Excel工作簿
                        if 'application/vnd.openxmlformats-officedocument.spreadsheetml' in content_types:
                            return "Microsoft Excel工作簿 (.xlsx)"
                            
                        # 检查PowerPoint演示文稿
                        if 'application/vnd.openxmlformats-officedocument.presentationml' in content_types:
                            return "Microsoft PowerPoint演示文稿 (.pptx)"
                    except:
                        pass
                
                # 通过目录结构判断
                # Word文档特征
                if any('word/document.xml' in f for f in file_list) or any('/word/' in f for f in file_list):
                    return "Microsoft Word文档 (.docx)"
                    
                # Excel工作簿特征
                if any('xl/workbook.xml' in f for f in file_list) or any('/xl/' in f for f in file_list):
                    return "Microsoft Excel工作簿 (.xlsx)"
                    
                # PowerPoint演示文稿特征
                if any('ppt/presentation.xml' in f for f in file_list) or any('/ppt/' in f for f in file_list):
                    return "Microsoft PowerPoint演示文稿 (.pptx)"
                
            # 如果以上都没匹配，但确认是ZIP文件，可能是其他OOXML格式
            return "Microsoft Office Open XML文档 (未知类型)"
            
        except Exception as e:
            if self.verbose:
                print(f"分析OOXML文件时出错: {e}")
            return "Microsoft Office Open XML文档 (可能已损坏)"
    
    def _guess_office_type_by_content(self, file_path):
        """通过文件内容特征猜测Office文档类型"""
        try:
            # 读取较多内容进行深度分析
            with open(file_path, 'rb') as f:
                content = f.read(32768)  # 读取前32KB
                
            # 首先检查是否包含Office文档特征
            office_markers = [b'Microsoft', b'Office', b'Document', b'Workbook', 
                              b'PowerPoint', b'Excel', b'Word', b'Worksheet']
                              
            office_markers_found = [marker for marker in office_markers if marker in content]
            if not office_markers_found:
                return None  # 不太可能是Office文档
                
            # 统计各种Office类型特征出现次数
            marker_counts = {
                'doc': 0,
                'xls': 0,
                'ppt': 0
            }
            
            # Word文档特征
            doc_markers = [b'Word', b'Document', b'DocFile', b'MSWordDoc', b'.docx', b'.doc',
                           b'w:document', b'word/document.xml', b'wordDocument']
            for marker in doc_markers:
                marker_counts['doc'] += content.count(marker)
                
            # Excel工作簿特征
            xls_markers = [b'Excel', b'Workbook', b'Worksheet', b'spreadsheet', b'.xlsx', b'.xls',
                           b'xl/workbook.xml', b'xl:workbook', b'sst', b'Sheet', b'x:sheet']
            for marker in xls_markers:
                marker_counts['xls'] += content.count(marker)
                
            # PowerPoint演示文稿特征
            ppt_markers = [b'PowerPoint', b'Presentation', b'Slide', b'.pptx', b'.ppt',
                           b'ppt/presentation.xml', b'p:presentation', b'slideshow']
            for marker in ppt_markers:
                marker_counts['ppt'] += content.count(marker)
                
            # 确定最可能的类型
            max_type = max(marker_counts.items(), key=lambda x: x[1])
            if max_type[1] > 0:
                if max_type[0] == 'doc':
                    # 再次判断是.doc还是.docx
                    if b'word/document.xml' in content or b'Content_Types' in content:
                        return "可能是Microsoft Word文档 (.docx) [基于内容特征判断]"
                    else:
                        return "可能是Microsoft Word文档 (.doc) [基于内容特征判断]"
                        
                elif max_type[0] == 'xls':
                    # 再次判断是.xls还是.xlsx
                    if b'xl/workbook.xml' in content or b'Content_Types' in content:
                        return "可能是Microsoft Excel工作簿 (.xlsx) [基于内容特征判断]"
                    else:
                        return "可能是Microsoft Excel工作簿 (.xls) [基于内容特征判断]"
                        
                elif max_type[0] == 'ppt':
                    # 再次判断是.ppt还是.pptx
                    if b'ppt/presentation.xml' in content or b'Content_Types' in content:
                        return "可能是Microsoft PowerPoint演示文稿 (.pptx) [基于内容特征判断]"
                    else:
                        return "可能是Microsoft PowerPoint演示文稿 (.ppt) [基于内容特征判断]"
            
            return "可能是Office文档 (具体类型未知) [基于内容特征判断]"
            
        except Exception as e:
            if self.verbose:
                print(f"通过内容猜测Office类型时出错: {e}")
            return None

    def _check_deeper_structure(self, file_path, header_hex):
        """深度检查文件结构以确定更具体的文件类型"""
        # 首先尝试使用专门的Office文档检测
        office_type = self._check_office_signatures(file_path)
        if office_type:
            return office_type
            
        # 如果是ZIP格式，检查内部结构
        if header_hex.startswith(b'504B0304'):
            try:
                import zipfile
                if not zipfile.is_zipfile(file_path):
                    return None

                with zipfile.ZipFile(file_path) as zip_file:
                    file_list = zip_file.namelist()
                    
                    # 检查AndroidAPK
                    if 'AndroidManifest.xml' in file_list:
                        return "Android应用程序包 (.apk)"
                    # 检查Java JAR
                    elif any(f.endswith('.class') for f in file_list) or 'META-INF/MANIFEST.MF' in file_list:
                        return "Java归档文件 (.jar)"
                    # 检查OpenDocument格式
                    elif 'mimetype' in file_list:
                        try:
                            mimetype = zip_file.read('mimetype').decode('utf-8')
                            if 'application/vnd.oasis.opendocument.text' in mimetype:
                                return "OpenDocument文本文档 (.odt)"
                            elif 'application/vnd.oasis.opendocument.spreadsheet' in mimetype:
                                return "OpenDocument电子表格 (.ods)"
                            elif 'application/vnd.oasis.opendocument.presentation' in mimetype:
                                return "OpenDocument演示文稿 (.odp)"
                        except:
                            pass
            except Exception as e:
                if self.verbose:
                    print(f"深度检查ZIP结构失败: {e}")
                return None

        # 检查RIFF格式
        elif header_hex.startswith(b'52494646'):
            try:
                with open(file_path, 'rb') as file:
                    # 跳过RIFF标记和大小
                    file.seek(8)
                    format_type = file.read(4)
                    
                    if format_type == b'WEBP':
                        return "WebP图像 (.webp)"
                    elif format_type == b'WAVE':
                        return "WAV音频 (.wav)"
                    elif format_type == b'AVI ':
                        return "AVI视频 (.avi)"
            except Exception as e:
                if self.verbose:
                    print(f"深度检查RIFF结构失败: {e}")
                return None

        return None



    def detect(self, file_path):
        """检测单个文件的签名并识别类型"""
        try:
            if not os.path.exists(file_path):
                return {"file_path": file_path, "error": "文件不存在", "type": "未知"}
                
            if os.path.isdir(file_path):
                return {"file_path": file_path, "error": "这是一个目录，不是文件", "type": "目录"}
                
            # 如果文件大小为0，直接返回
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {"file_path": file_path, "type": "空文件", "size": 0}
                
            header = self._read_file_header(file_path)
            if not header:
                return {"file_path": file_path, "error": "无法读取文件", "type": "未知"}
            
            header_hex = binascii.hexlify(header).upper()
            
            # 首先尝试特殊处理Office文档
            office_type = self._check_office_signatures(file_path)
            if office_type:
                return {
                    "file_path": file_path,
                    "type": office_type,
                    "size": file_size,
                    "header_hex": header_hex[:32].decode()
                }
            
            # 检查标准文件签名匹配
            for signature, file_type in self.signatures.items():
                if header_hex.startswith(signature):
                    # 尝试进行深度检查以获取更具体的文件类型
                    specific_type = self._check_deeper_structure(file_path, header_hex)
                    
                    # 如果深度检查成功，则使用更具体的类型
                    detected_type = specific_type if specific_type else file_type
                    
                    return {
                        "file_path": file_path,
                        "signature": signature.decode(),
                        "type": detected_type,
                        "size": file_size,
                        "header_hex": header_hex[:32].decode()
                    }
            
            # 如果没有找到匹配，尝试使用文件扩展名
            _, ext = os.path.splitext(file_path)
            if ext:
                ext = ext.lower()
                extensions = {
                    '.txt': '文本文件',
                    '.log': '日志文件',
                    '.ini': '配置文件',
                    '.conf': '配置文件',
                    '.cfg': '配置文件',
                    '.csv': 'CSV数据文件',
                    '.json': 'JSON数据文件',
                    '.xml': 'XML数据文件',
                    '.html': 'HTML文件',
                    '.htm': 'HTML文件',
                    '.css': 'CSS样式表',
                    '.js': 'JavaScript文件',
                    '.py': 'Python源代码',
                    '.java': 'Java源代码',
                    '.c': 'C源代码',
                    '.cpp': 'C++源代码',
                    '.h': 'C/C++头文件',
                    '.sh': 'Shell脚本',
                    '.bat': 'Windows批处理文件',
                    '.ps1': 'PowerShell脚本',
                    '.sql': 'SQL脚本',
                    '.md': 'Markdown文档',
                    '.rst': 'reStructuredText文档',
                    '.yaml': 'YAML数据文件',
                    '.yml': 'YAML数据文件',
                    '.toml': 'TOML配置文件',
                    '.db': '数据库文件',
                    '.sqlite': 'SQLite数据库',
                    '.mp3': 'MP3音频',
                    '.mp4': 'MP4视频',
                    '.avi': 'AVI视频',
                    '.mov': 'QuickTime视频',
                    '.mkv': 'Matroska视频',
                    '.jpg': 'JPEG图像',
                    '.jpeg': 'JPEG图像',
                    '.png': 'PNG图像',
                    '.gif': 'GIF图像',
                    '.bmp': 'BMP图像',
                    '.tif': 'TIFF图像',
                    '.tiff': 'TIFF图像',
                    '.webp': 'WebP图像',
                    '.pdf': 'PDF文档',
                    '.doc': 'Word文档',
                    '.docx': 'Word文档',
                    '.xls': 'Excel电子表格',
                    '.xlsx': 'Excel电子表格',
                    '.ppt': 'PowerPoint演示文稿',
                    '.pptx': 'PowerPoint演示文稿',
                    '.zip': 'ZIP压缩包',
                    '.rar': 'RAR压缩包',
                    '.7z': '7-Zip压缩包',
                    '.tar': 'TAR归档',
                    '.gz': 'GZIP压缩包',
                    '.bz2': 'BZIP2压缩包',
                }
                
                file_type = extensions.get(ext, f"未知文件类型 (扩展名: {ext})")
                return {
                    "file_path": file_path,
                    "signature": "无匹配签名",
                    "type": f"{file_type} (基于文件扩展名)",
                    "size": file_size,
                    "header_hex": header_hex[:32].decode()
                }
            
            # 尝试检测是否为纯文本文件
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)
                    return {
                        "file_path": file_path,
                        "signature": "无匹配签名",
                        "type": "可能是UTF-8文本文件",
                        "size": file_size,
                        "header_hex": header_hex[:32].decode(),
                        "encoding": "UTF-8"
                    }
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'r', encoding='gbk') as f:
                        f.read(1024)
                        return {
                            "file_path": file_path,
                            "signature": "无匹配签名",
                            "type": "可能是GBK文本文件",
                            "size": file_size,
                            "header_hex": header_hex[:32].decode(),
                            "encoding": "GBK"
                        }
                except UnicodeDecodeError:
                    pass
                
            # 对于二进制文件，尝试使用更多启发式分析
            try:
                # 检查文件内容的前4KB，寻找特征字符串
                with open(file_path, 'rb') as f:
                    content_sample = f.read(4096)
                    
                # 分析内容样本中的可打印字符比例
                printable_chars = sum(1 for c in content_sample if c >= 32 and c <= 126)
                printable_ratio = printable_chars / len(content_sample) if content_sample else 0
                
                # 检查是否包含NULL字节
                has_nulls = b'\x00' in content_sample
                
                # 根据分析结果猜测类型
                if printable_ratio > 0.75 and not has_nulls:
                    return {
                        "file_path": file_path,
                        "signature": "无匹配签名",
                        "type": "可能是不带BOM的文本文件 (高可打印字符比例)",
                        "size": file_size,
                        "header_hex": header_hex[:32].decode(),
                        "printable_ratio": f"{printable_ratio:.2f}"
                    }
                elif printable_ratio > 0.3 and has_nulls:
                    return {
                        "file_path": file_path,
                        "signature": "无匹配签名",
                        "type": "可能是包含二进制数据的数据文件",
                        "size": file_size,
                        "header_hex": header_hex[:32].decode(),
                        "printable_ratio": f"{printable_ratio:.2f}"
                    }
            except Exception as e:
                if self.verbose:
                    print(f"分析文件内容时出错: {e}")
                    
            # 完全未知的二进制文件
            return {
                "file_path": file_path,
                "signature": "无匹配签名",
                "type": "未知二进制文件",
                "size": file_size,
                "header_hex": header_hex[:32].decode()
            }
            
        except Exception as e:
            if self.verbose:
                print(f"文件检测过程出错: {e}")
            return {
                "file_path": file_path,
                "error": str(e),
                "type": "检测过程出错"
            }

    def scan_directory(self, directory_path, recursive=False):
        """扫描目录中的所有文件并检测其类型"""
        results = []
        
        if not os.path.exists(directory_path):
            print(f"错误: 目录不存在: {directory_path}")
            return results
        
        if not os.path.isdir(directory_path):
            print(f"错误: 指定路径不是目录: {directory_path}")
            return results
            
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    result = self.detect(file_path)
                    results.append(result)
                except Exception as e:
                    if self.verbose:
                        print(f"处理文件时出错 {file_path}: {e}")
                    results.append({
                        "file_path": file_path,
                        "error": str(e),
                        "type": "处理出错"
                    })
                    
            # 如果不是递归模式，只处理顶级目录
            if not recursive:
                break
                
        return results

def main():
    parser = argparse.ArgumentParser(description='文件签名检测器 - 通过文件头部的二进制签名识别文件类型')
    parser.add_argument('path', help='要检测的文件或目录的路径')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归扫描子目录')
    parser.add_argument('-o', '--output', help='输出结果的文件路径 (支持格式: json, csv, txt)')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'text'], default='text', 
                        help='输出格式: json, csv 或 text (默认: text)')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细输出')
    parser.add_argument('--batch', help='批量扫描多个目录，提供包含路径列表的文件')
    parser.add_argument('--repair', action='store_true', help='尝试修复损坏的文件签名（仅用于分析）')
    parser.add_argument('--office-only', action='store_true', help='仅检测Office文档类型')
    parser.add_argument('--csv-summary', help='将类型统计汇总输出到CSV文件')
    parser.add_argument('--filter', help='按文件类型过滤结果（例如：doc,xls,pdf）')
    
    args = parser.parse_args()
    
    # 创建文件签名探测器实例
    detector = FileSignatureDetector(verbose=args.verbose)
    
    # 处理批量扫描
    if args.batch:
        if not os.path.exists(args.batch):
            print(f"错误: 批处理文件不存在: {args.batch}")
            return 1
            
        with open(args.batch, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f if line.strip()]
            
        all_results = []
        for path in paths:
            print(f"处理路径: {path}")
            if os.path.isdir(path):
                results = detector.scan_directory(path, args.recursive)
            elif os.path.isfile(path):
                results = [detector.detect(path)]
            else:
                print(f"警告: 跳过不存在的路径: {path}")
                continue
                
            all_results.extend(results)
            
        results = all_results
    else:
        # 检测路径是文件还是目录
        if os.path.isfile(args.path):
            # 单个文件处理
            result = detector.detect(args.path)
            results = [result]
            
            # 打印结果
            print(f"\n文件路径: {result['file_path']}")
            print(f"文件大小: {result['size']} 字节")
            print(f"文件类型: {result['type']}")
            print(f"文件签名: {result.get('signature', '无')}")
            print(f"文件头部(HEX): {result.get('header_hex', '无')}")
            if 'encoding' in result:
                print(f"文件编码: {result['encoding']}")
            if 'error' in result:
                print(f"错误信息: {result['error']}")
            
        elif os.path.isdir(args.path):
            # 目录处理
            print(f"正在扫描目录: {args.path}{' (包含子目录)' if args.recursive else ''}")
            results = detector.scan_directory(args.path, args.recursive)
        else:
            print(f"错误: 路径不存在或无法访问: {args.path}")
            return 1
    
    # 如果只关心Office文档，过滤结果
    if args.office_only:
        office_types = ['Word', 'Excel', 'PowerPoint', 'Office', '.doc', '.xls', '.ppt']
        results = [r for r in results if any(t in r.get('type', '') for t in office_types)]
    
    # 如果设置了过滤器，应用过滤
    if args.filter:
        filter_types = [t.strip().lower() for t in args.filter.split(',')]
        results = [r for r in results if any(t in r.get('type', '').lower() for t in filter_types)]
    
    # 统计结果
    total = len(results)
    if total == 0:
        print("没有找到匹配的文件")
        return 0
        
    error_count = sum(1 for r in results if 'error' in r)
    unknown_count = sum(1 for r in results if r.get('type', '').startswith('未知'))
    
    # 按类型分组
    type_counts = {}
    for r in results:
        file_type = r.get('type', '未知')
        if file_type not in type_counts:
            type_counts[file_type] = 0
        type_counts[file_type] += 1
    
    # 打印统计结果
    print(f"\n扫描完成! 共处理 {total} 个文件")
    print(f"成功识别: {total - error_count - unknown_count} 个文件")
    print(f"识别失败: {unknown_count} 个文件")
    print(f"处理错误: {error_count} 个文件")
    
    print("\n文件类型统计:")
    for file_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:  # 只显示数量大于0的类型
            print(f"  {file_type}: {count} 个文件")
            
    # 如果文件数量不多，显示详细结果
    if total <= 20 or args.verbose:
        print("\n详细结果:")
        for i, result in enumerate(results):
            print(f"\n{i+1}. {result['file_path']}")
            print(f"   文件类型: {result.get('type', '未知')}")
            print(f"   文件大小: {result.get('size', 0)} 字节")
            if 'error' in result:
                print(f"   错误: {result['error']}")
    
    # 如果指定了输出文件，保存结果
    if args.output:
        output_format = args.format.lower()
        if '.' in args.output:
            ext = args.output.split('.')[-1].lower()
            if ext in ['json', 'csv', 'txt']:
                output_format = ext
        
        try:
            if output_format == 'json':
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
            elif output_format == 'csv':
                with open(args.output, 'w', encoding='utf-8', newline='') as f:
                    if results:
                        # 确定所有结果中包含的字段
                        all_keys = set()
                        for result in results:
                            all_keys.update(result.keys())
                        
                        # 排序字段，重要字段放前面
                        important_keys = ['file_path', 'type', 'size', 'signature', 'error']
                        ordered_keys = [k for k in important_keys if k in all_keys]
                        ordered_keys.extend([k for k in all_keys if k not in important_keys])
                        
                        writer = csv.DictWriter(f, fieldnames=ordered_keys)
                        writer.writeheader()
                        
                        # 处理缺失字段
                        for result in results:
                            row = {k: result.get(k, '') for k in ordered_keys}
                            writer.writerow(row)
            else:  # text format
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(f"文件签名检测报告\n")
                    f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"检测路径: {args.path}\n\n")
                    
                    for i, result in enumerate(results):
                        f.write(f"{i+1}. {result['file_path']}\n")
                        f.write(f"   文件类型: {result.get('type', '未知')}\n")
                        f.write(f"   文件大小: {result.get('size', 0)} 字节\n")
                        if 'signature' in result:
                            f.write(f"   文件签名: {result['signature']}\n")
                        if 'error' in result:
                            f.write(f"   错误: {result['error']}\n")
                        f.write("\n")
                        
                    # 写入统计信息
                    f.write("\n文件类型统计:\n")
                    for file_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                        if count > 0:  # 只显示数量大于0的类型
                            f.write(f"  {file_type}: {count} 个文件\n")
            
            print(f"\n结果已保存到: {args.output}")
        except Exception as e:
            print(f"保存结果时出错: {e}")
    
    # 如果需要生成CSV汇总报告
    if args.csv_summary:
        try:
            with open(args.csv_summary, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['文件类型', '文件数量', '占比(%)', '字节总数', '平均大小(字节)'])
                
                # 计算每种类型的总字节数和平均大小
                type_sizes = {}
                for file_type in type_counts:
                    type_files = [r for r in results if r.get('type', '未知') == file_type]
                    total_size = sum(r.get('size', 0) for r in type_files)
                    avg_size = total_size / len(type_files) if type_files else 0
                    percentage = (type_counts[file_type] / total) * 100
                    
                    writer.writerow([file_type, type_counts[file_type], f"{percentage:.2f}", 
                                    total_size, f"{avg_size:.2f}"])
                
                print(f"\n类型统计汇总已保存到: {args.csv_summary}")
        except Exception as e:
            print(f"保存类型统计时出错: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
