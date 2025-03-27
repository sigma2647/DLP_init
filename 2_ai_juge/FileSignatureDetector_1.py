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
    """
    增强型文件签名检测器，使用文件头部签名、扩展名和内容特征识别文件类型
    """

    # FILE_SIGNATURES, MIME_TYPES, and SKIP_EXTENSIONS are kept as is

    def __init__(self):
        """初始化文件签名检测器，使用python-magic"""
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
        
        # 编译正则表达式，提高性能
        self.ole_pattern = re.compile(r'(WordDocument|Workbook|PowerPoint Document|Microsoft (?:Word|Excel|PowerPoint))', re.IGNORECASE)
        self.excel_cell_pattern = re.compile(r'Cell[^a-zA-Z0-9]', re.IGNORECASE)
        self.excel_sheet_pattern = re.compile(r'Sheet\d', re.IGNORECASE)
        self.internal_stream_pattern = re.compile(r'^\[\d+\].+|^~\$|^__SRP_\d+$|^__substg1\.0_|^__attach_version1\.0_|^__properties_version1\.0$|^MsoDataStore|Thumbs\.db$|\.tmp$')

    def _is_internal_stream(self, file_name: str) -> bool:
        """
        检查文件是否为内部流文件（如OLE文件中的那些）
        
        Args:
            file_name: 要检查的文件名
            
        Returns:
            如果文件是内部流，则为True，否则为False
        """
        return bool(self.internal_stream_pattern.search(file_name))

    def read_file_header(self, file_path: str, bytes_to_read: int = 32) -> str:
        """
        读取文件的前N个字节并返回十六进制字符串

        Args:
            file_path: 文件路径
            bytes_to_read: 要读取的字节数

        Returns:
            文件头的大写十六进制字符串
        """
        try:
            with open(file_path, "rb") as f:
                header = f.read(bytes_to_read)
            return binascii.hexlify(header).decode("ascii").upper()
        except Exception as e:
            logger.error(f"读取文件头出错: {file_path} - {e}")
            return ""

    def get_magic_mime_type(self, file_path: str) -> str:
        """
        使用python-magic检测MIME类型

        Args:
            file_path: 文件路径

        Returns:
            MIME类型字符串，失败时返回空字符串
        """
        if not self.mime:
            return ""

        try:
            # 处理非ASCII文件名或含空格的路径
            normalized_path = os.path.normpath(os.path.abspath(file_path))
            return self.mime.from_file(normalized_path)
        except Exception as e:
            logger.error(f"Magic MIME类型检测失败: {file_path} - {e}")
            return ""

    def inspect_zip_content(self, file_path: str) -> Optional[str]:
        """
        检查ZIP文件内容以确定是否为OOXML文档

        Args:
            file_path: ZIP文件路径

        Returns:
            如果确定，返回MIME类型，否则返回None
        """
        try:
            with zipfile.ZipFile(file_path) as zip_file:
                file_list = set(zip_file.namelist())  # 使用集合提高查找效率

                # 检查DOCX
                if "word/document.xml" in file_list:
                    return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                # 检查XLSX
                elif "xl/workbook.xml" in file_list:
                    return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                # 检查PPTX
                elif "ppt/presentation.xml" in file_list:
                    return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                # 检查ODT (OpenDocument Text)
                elif "mimetype" in file_list and "content.xml" in file_list:
                    try:
                        mimetype = zip_file.read("mimetype").decode('utf-8').strip()
                        if mimetype == "application/vnd.oasis.opendocument.text":
                            return "application/vnd.oasis.opendocument.text"
                        elif mimetype == "application/vnd.oasis.opendocument.spreadsheet":
                            return "application/vnd.oasis.opendocument.spreadsheet"
                        elif mimetype == "application/vnd.oasis.opendocument.presentation":
                            return "application/vnd.oasis.opendocument.presentation"
                    except:
                        pass

                # 如果没有找到特定标记，它是通用ZIP
                return "application/zip"
        except zipfile.BadZipFile:
            logger.warning(f"无效的ZIP文件: {file_path}")
            return None
        except Exception as e:
            logger.warning(f"ZIP内容检查失败: {file_path} - {e}")
            return None

    def inspect_ole_content(self, file_path: str) -> Optional[str]:
        """
        检查OLE文件内容以确定是否为特定Office文档类型

        Args:
            file_path: OLE文件路径

        Returns:
            如果确定，返回MIME类型，否则返回None
        """
        try:
            # 首先，通过扩展名快速判断
            ext = Path(file_path).suffix.lower()
            if ext == ".doc":
                return "application/msword"
            elif ext == ".xls":
                return "application/vnd.ms-excel"
            elif ext == ".ppt":
                return "application/vnd.ms-powerpoint"

            # 如果扩展名不能帮助，尝试深度分析
            # 读取较大的块以搜索标记
            with open(file_path, "rb") as f:
                content = f.read(16384)  # 读取16KB

            content_str = content.decode("latin1", errors="ignore")

            # 使用预编译正则表达式检查特定标记
            if self.ole_pattern.search(content_str):
                # 检查Word标记
                if "WordDocument" in content_str or "Microsoft Word" in content_str:
                    return "application/msword"
                
                # 检查Excel标记
                if "Workbook" in content_str or "Microsoft Excel" in content_str:
                    return "application/vnd.ms-excel"
                
                # 检查单元格和工作表模式（Excel特有）
                if self.excel_cell_pattern.search(content_str) and self.excel_sheet_pattern.search(content_str):
                    return "application/vnd.ms-excel"
                
                # 检查PowerPoint标记
                if "PowerPoint Document" in content_str or "Microsoft PowerPoint" in content_str:
                    return "application/vnd.ms-powerpoint"

            # 检查二进制模式，查找Excel特有的标记
            if b"Standard Jet DB" in content or b"Excel.Sheet" in content:
                return "application/vnd.ms-excel"

            # 如果没有找到特定标记，它是通用OLE文件
            return "application/x-ole-storage"
        except Exception as e:
            logger.warning(f"OLE内容检查失败: {file_path} - {e}")
            return None

    def detect_file_type(self, file_path: str) -> str:
        """
        综合检测文件类型，返回MIME类型

        Args:
            file_path: 文件路径

        Returns:
            检测到的MIME类型
        """
        try:
            # 基本文件信息
            file_size = os.path.getsize(file_path)
            file_extension = Path(file_path).suffix.lower()
            expected_mime = self.MIME_TYPES.get(
                file_extension, "application/octet-stream"
            )

            # 跳过非常小或空的文件
            if file_size == 0:
                return "application/octet-stream"

            # 缓存机制 - 使用文件路径和修改时间作为键
            file_mtime = os.path.getmtime(file_path)
            cache_key = f"{file_path}:{file_mtime}"
            
            # 可以在这里添加缓存查找逻辑
            # if cache_key in self.mime_cache:
            #    return self.mime_cache[cache_key]

            # 读取文件头部（前32字节）
            header_hex = self.read_file_header(file_path, 32)

            # 获取magic MIME类型（如果可用）
            magic_mime = self.get_magic_mime_type(file_path) if self.mime else ""

            # 通过文件头部签名检测
            detected_mime = "application/octet-stream"

            # 检查PDF签名
            if header_hex.startswith("25504446"):
                return "application/pdf"
            
            # 检查图像格式
            elif header_hex.startswith("FFD8FF"):
                return "image/jpeg"
            elif header_hex.startswith("89504E47"):
                return "image/png"
            elif header_hex.startswith("47494638"):
                return "image/gif"
            elif header_hex.startswith("424D"):
                return "image/bmp"
            
            # 检查音频/视频
            elif header_hex.startswith("494433") or header_hex.startswith("FFFB"):
                return "audio/mpeg"
            elif header_hex.startswith("52494646") and "57415645" in header_hex:
                return "audio/wav"
            elif header_hex.startswith("00000020667479704D3441"):
                return "video/mp4"
            
            # 检查ZIP签名
            elif header_hex.startswith("504B0304"):  # ZIP签名
                zip_mime = self.inspect_zip_content(file_path)
                if zip_mime:
                    return zip_mime

            # 检查OLE签名
            elif header_hex.startswith("D0CF11E0A1B11AE1"):  # OLE签名
                ole_mime = self.inspect_ole_content(file_path)
                if ole_mime:
                    return ole_mime

            # 检查压缩文件
            elif header_hex.startswith("526172"):  # RAR
                return "application/x-rar"
            elif header_hex.startswith("377ABCAF"):  # 7-Zip
                return "application/x-7z-compressed"
            elif header_hex.startswith("1F8B08"):  # GZIP
                return "application/gzip"

            # 如果通过签名无法识别，尝试使用magic库
            if magic_mime and magic_mime != "application/octet-stream":
                return magic_mime

            # 检查文本文件 - 尝试读取并解码前4KB
            if file_size < 1024 * 1024 * 5:  # 小于5MB的文件
                try:
                    with open(file_path, "rb") as f:
                        content = f.read(4096)
                    
                    # 尝试以UTF-8解码
                    try:
                        content.decode('utf-8')
                        
                        # 检查具体的文本格式
                        text_content = content.decode('utf-8')
                        
                        # 检查JSON
                        if file_extension == '.json' or (text_content.strip().startswith('{') and text_content.strip().endswith('}')):
                            return "application/json"
                        
                        # 检查XML
                        if file_extension == '.xml' or (text_content.strip().startswith('<') and text_content.strip().endswith('>')):
                            return "text/xml"
                        
                        # 检查CSV
                        if file_extension == '.csv' or ',' in text_content and '\n' in text_content:
                            comma_count = text_content.count(',')
                            newline_count = text_content.count('\n')
                            if comma_count > 0 and newline_count > 0 and comma_count / newline_count > 1:
                                return "text/csv"
                        
                        # 检查Markdown
                        if file_extension == '.md' or '##' in text_content or '```' in text_content:
                            return "text/markdown"
                        
                        # 检查YAML
                        if file_extension in ['.yml', '.yaml'] or ':' in text_content and '\n' in text_content:
                            return "application/yaml"
                        
                        # 默认为纯文本
                        return "text/plain"
                    except UnicodeDecodeError:
                        pass
                except:
                    pass

            # 最后尝试使用扩展名
            if file_extension and expected_mime != "application/octet-stream":
                return expected_mime

            # 如果一切都失败了，返回二进制流类型
            return "application/octet-stream"

        except Exception as e:
            logger.error(f"文件类型检测失败: {file_path} - {e}")
            return "application/octet-stream"

    def get_all_files(self, directory: str) -> List[str]:
        """
        递归获取目录中的所有文件，过滤掉某些类型

        Args:
            directory: 要扫描的目录路径

        Returns:
            文件路径列表
        """
        files = []
        try:
            # 更高效的文件遍历
            for root, dirs, file_names in os.walk(directory):
                # 跳过隐藏目录
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file_name in file_names:
                    # 跳过隐藏文件和Office临时文件
                    if file_name.startswith(".") or file_name.startswith("~$"):
                        continue

                    # 跳过Office内部流文件
                    if self._is_internal_stream(file_name):
                        continue

                    file_path = os.path.join(root, file_name)
                    
                    # 跳过已知的二进制格式
                    ext = Path(file_path).suffix.lower()
                    if ext in self.SKIP_EXTENSIONS:
                        continue
                    
                    files.append(file_path)
        except Exception as e:
            logger.error(f"遍历目录失败: {directory} - {e}")
        
        return files

    def check_file_signature(self, file_path: str) -> Dict:
        """
        检查文件签名并返回详细信息

        Args:
            file_path: 文件路径

        Returns:
            包含详细文件签名信息的字典
        """
        try:
            mime_type = self.detect_file_type(file_path)

            # 获取文件头
            header_hex = self.read_file_header(file_path, 32)

            # 获取更多元数据
            file_size = os.path.getsize(file_path)
            creation_time = os.path.getctime(file_path)
            modification_time = os.path.getmtime(file_path)
            
            return {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "extension": Path(file_path).suffix.lower(),
                "mime_type": mime_type,
                "header_hex": header_hex,
                "created_at": datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M:%S"),
                "modified_at": datetime.fromtimestamp(modification_time).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception as e:
            logger.error(f"检查文件签名失败: {file_path} - {e}")
            return {
                "file_path": file_path,
                "error": str(e)
            }

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
