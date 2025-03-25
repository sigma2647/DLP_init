import os
import pandas as pd
import xlrd
import openpyxl
import tempfile
import traceback
import win32com.client  # 新增win32com库

def extract_excel_content(file_path):
    """Try multiple methods to extract content from an Excel file"""
    print(f"原始文件路径: {file_path}")
    print(f"原始文件大小: {os.path.getsize(file_path)} 字节")
    
    # Try different extraction methods
    methods = [
        extract_with_win32com,  # 添加win32com方法作为首选
        extract_with_pandas,
        extract_with_xlrd,
        extract_with_openpyxl,
        extract_with_binary_read
    ]
    
    results = []
    
    for method in methods:
        try:
            print(f"\n尝试使用 {method.__name__} 方法提取内容...")
            content = method(file_path)
            if content and content.strip():
                print(f"使用 {method.__name__} 成功提取了 {len(content)} 字符")
                results.append((method.__name__, content))
            else:
                print(f"使用 {method.__name__} 没有提取到内容")
        except Exception as e:
            print(f"使用 {method.__name__} 提取时出错: {str(e)}")
            traceback.print_exc()
    
    # Return results from all successful methods
    return results

# 新增的win32com方法
def extract_with_win32com(file_path):
    """使用win32com提取Word文档内容"""
    try:
        # 创建Word应用实例
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False
        
        # 获取文件的绝对路径
        abs_path = os.path.abspath(file_path)
        
        try:
            # 尝试打开文件为Word文档
            doc = word.Documents.Open(abs_path)
            
            # 提取文档内容
            content = doc.Content.Text
            
            # 提取段落
            paragraphs = []
            for i in range(doc.Paragraphs.Count):
                paragraph_text = doc.Paragraphs(i+1).Range.Text
                if paragraph_text.strip():
                    paragraphs.append(paragraph_text)
            
            # 提取表格内容（如果有）
            tables_content = []
            for i in range(doc.Tables.Count):
                table = doc.Tables(i+1)
                table_text = f"表格 {i+1}:\n"
                
                for row in range(1, table.Rows.Count + 1):
                    row_data = []
                    for col in range(1, table.Columns.Count + 1):
                        try:
                            cell_text = table.Cell(row, col).Range.Text.replace("\r", "").strip()
                            row_data.append(cell_text)
                        except:
                            row_data.append("")
                    
                    table_text += " | ".join(row_data) + "\n"
                
                tables_content.append(table_text)
            
            # 关闭文档
            doc.Close(False)
            
            # 整合所有内容
            full_content = "文档文本内容:\n" + content + "\n\n"
            
            if paragraphs:
                full_content += "段落内容:\n" + "\n".join(paragraphs) + "\n\n"
            
            if tables_content:
                full_content += "表格内容:\n" + "\n\n".join(tables_content)
            
            return full_content
            
        finally:
            # 退出Word应用
            word.Quit()
            
    except Exception as e:
        print(f"Win32COM提取失败: {str(e)}")
        return ""

# 以下是原有的方法，保持不变
def extract_with_pandas(file_path):
    """使用pandas提取Excel内容"""
    # 原有代码保持不变
    try:
        # 尝试不同的引擎
        engines = ['openpyxl', 'xlrd']
        content = ""
        
        for engine in engines:
            try:
                print(f"尝试使用pandas的{engine}引擎...")
                df = pd.read_excel(file_path, engine=engine)
                sheet_content = df.to_string(index=False)
                if sheet_content:
                    content += f"Sheet (使用 {engine}):\n{sheet_content}\n\n"
            except Exception as e:
                print(f"使用pandas的{engine}引擎失败: {str(e)}")
        
        return content
    except Exception as e:
        print(f"Pandas提取失败: {str(e)}")
        return ""

def extract_with_xlrd(file_path):
    """使用xlrd直接提取Excel内容（适用于.xls格式）"""
    # 原有代码保持不变
    try:
        workbook = xlrd.open_workbook(file_path, formatting_info=False)
        content = []
        
        for sheet_idx in range(workbook.nsheets):
            sheet = workbook.sheet_by_index(sheet_idx)
            sheet_content = f"表格名称: {sheet.name}\n"
            
            # 提取表头
            headers = []
            for col in range(sheet.ncols):
                headers.append(str(sheet.cell_value(0, col)))
            
            sheet_content += "表头: " + ", ".join(headers) + "\n\n"
            
            # 提取数据
            for row in range(1, sheet.nrows):
                row_data = []
                for col in range(sheet.ncols):
                    cell_value = sheet.cell_value(row, col)
                    cell_type = sheet.cell_type(row, col)
                    
                    # 处理日期类型
                    if cell_type == xlrd.XL_CELL_DATE:
                        try:
                            date_tuple = xlrd.xldate_as_tuple(cell_value, workbook.datemode)
                            cell_value = f"{date_tuple[0]}-{date_tuple[1]}-{date_tuple[2]}"
                        except:
                            pass
                    
                    row_data.append(str(cell_value))
                
                sheet_content += " | ".join(row_data) + "\n"
            
            content.append(sheet_content)
        
        return "\n\n".join(content)
    except Exception as e:
        print(f"XLRD提取失败: {str(e)}")
        return ""

def extract_with_openpyxl(file_path):
    """使用openpyxl提取Excel内容（适用于.xlsx格式）"""
    # 原有代码保持不变
    try:
        # 创建临时文件
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
        temp_file.close()
        
        # 复制原始文件到临时文件
        with open(file_path, 'rb') as src, open(temp_file.name, 'wb') as dst:
            dst.write(src.read())
        
        try:
            workbook = openpyxl.load_workbook(temp_file.name, read_only=True, data_only=True)
            content = []
            
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                sheet_content = f"表格名称: {sheet_name}\n"
                
                rows = list(sheet.rows)
                if not rows:
                    continue
                
                # 提取表头
                headers = [str(cell.value) for cell in rows[0]]
                sheet_content += "表头: " + ", ".join(headers) + "\n\n"
                
                # 提取数据
                for row in rows[1:]:
                    row_data = [str(cell.value if cell.value is not None else "") for cell in row]
                    sheet_content += " | ".join(row_data) + "\n"
                
                content.append(sheet_content)
            
            return "\n\n".join(content)
        finally:
            # 删除临时文件
            try:
                os.unlink(temp_file.name)
            except:
                pass
    except Exception as e:
        print(f"OpenPyXL提取失败: {str(e)}")
        return ""

def extract_with_binary_read(file_path):
    """以二进制方式读取Excel文件并提取可读文本"""
    # 原有代码保持不变
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        
        # 尝试以不同的编码解析文件
        encodings = ['utf-8', 'latin-1', 'ascii', 'gbk', 'gb2312', 'gb18030']
        all_decoded_text = ""
        
        for encoding in encodings:
            try:
                decoded = content.decode(encoding, errors='replace')
                
                # 过滤出可打印字符和基本控制字符
                printable_text = ''.join(c for c in decoded if c.isprintable() or c in ['\n', '\t', '\r', ' '])
                
                # 查找可能的单元格值
                # Excel中常见的字符串片段
                potential_cells = []
                lines = printable_text.split('\n')
                
                for line in lines:
                    # 跳过太短的行
                    if len(line.strip()) < 3:
                        continue
                    
                    # 跳过大量重复字符的行（可能是格式化字符）
                    if len(set(line)) < len(line) / 5:
                        continue
                    
                    potential_cells.append(line)
                
                cell_content = '\n'.join(potential_cells)
                
                # 只有当找到的文本超过当前总文本时才添加
                if len(cell_content) > len(all_decoded_text):
                    all_decoded_text = cell_content
                    print(f"使用编码 {encoding} 提取了 {len(cell_content)} 字符")
            except Exception as e:
                print(f"编码 {encoding} 解析失败: {str(e)}")
        
        return all_decoded_text
    except Exception as e:
        print(f"二进制读取失败: {str(e)}")
        return ""

def main():
    # 目标文件路径
    # file_path = r"C:\file\lab1\629926cb814bc3f06828a39a8333d172_1_to_content"
    file_path = r"C:\file\foooooo\d22235d6a6438c395531104ef96f590d_1"
    
    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return
    
    print("正在尝试多种方法提取Excel内容...")
    results = extract_excel_content(file_path)
    
    if results:
        print("\n" + "=" * 50)
        print(f"成功使用 {len(results)} 种方法提取内容")
        
        # 保存所有成功提取的内容
        for i, (method_name, content) in enumerate(results):
            output_file = f"{file_path}_excel_content_{i}_{method_name}.txt"
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(content)
            print(f"已将使用 {method_name} 提取的内容保存到: {output_file}")
            
            # 显示内容预览
            preview = content[:500] + ("..." if len(content) > 500 else "")
            print(f"\n{method_name} 提取的内容预览:\n{'-' * 50}\n{preview}\n{'-' * 50}")
    else:
        # 如果所有方法都失败，尝试使用系统file命令检测文件类型
        try:
            import subprocess
            process = subprocess.Popen(['file', file_path], stdout=subprocess.PIPE)
            output, error = process.communicate()
            if output:
                print(f"\n文件类型检测结果: {output.decode('utf-8')}")
        except:
            pass
            
        print("\n未能成功提取Excel内容，请尝试使用专业文件恢复工具")

if __name__ == "__main__":
    main()
