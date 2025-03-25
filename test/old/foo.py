import os
import shutil
from win32com import client

def extract_shapes_content(file_path):
    """提取Word文档中形状对象的内容"""
    try:
        # 创建临时文件
        temp_path = file_path + ".doc"
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # 复制原始文件
        shutil.copy2(file_path, temp_path)
        print(f"创建临时文件: {temp_path}")
        
        # 获取完整路径
        abs_temp_path = os.path.abspath(temp_path)
        
        # 创建Word应用程序对象
        word = client.Dispatch('Word.Application')
        word.Visible = False
        word.DisplayAlerts = 0
        
        print("正在打开文档...")
        doc = word.Documents.Open(abs_temp_path)
        print(f"文档已打开，包含 {doc.Shapes.Count} 个形状对象")
        
        # 收集形状对象内容
        shapes_content = []
        for i in range(1, doc.Shapes.Count + 1):
            try:
                shape = doc.Shapes(i)
                shape_type = shape.Type
                
                # 获取形状信息
                shape_info = f"形状 {i} (类型 {shape_type})"
                
                # 尝试获取文本框内容
                text_content = ""
                try:
                    if hasattr(shape, 'TextFrame') and shape.TextFrame.HasText:
                        text_content = shape.TextFrame.TextRange.Text
                    elif hasattr(shape, 'TextFrame2') and shape.TextFrame2.HasText:
                        text_content = shape.TextFrame2.TextRange.Text
                except:
                    pass
                
                # 如果有文本内容，添加到结果中
                if text_content and text_content.strip():
                    shapes_content.append(f"{shape_info}:\n{text_content}")
                    print(f"从形状 {i} 提取了 {len(text_content)} 个字符")
                else:
                    print(f"形状 {i} 没有文本内容")
                
                # 如果是图片，获取图片信息
                if shape_type == 13:  # 13表示图片
                    shapes_content.append(f"{shape_info}: [图片]")
                    print(f"形状 {i} 是图片")
                
                # 如果是组合形状，尝试获取子形状信息
                if shape_type == 17:  # 17表示组合形状
                    try:
                        if hasattr(shape, 'GroupItems'):
                            group_info = f"组合形状 {i} 包含 {shape.GroupItems.Count} 个子形状"
                            shapes_content.append(group_info)
                            print(group_info)
                    except:
                        pass
            except Exception as inner_e:
                print(f"处理形状 {i} 时出错: {inner_e}")
        
        # 关闭文档
        doc.Close(SaveChanges=False)
        word.Quit()
        
        # 删除临时文件
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        return "\n\n".join(shapes_content) if shapes_content else "未找到形状对象内容"
    except Exception as e:
        print(f"提取形状内容时出错: {e}")
        # 清理资源
        try:
            if 'doc' in locals():
                doc.Close(SaveChanges=False)
            if 'word' in locals():
                word.Quit()
        except:
            pass
        
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
        
        return f"提取形状内容时出错: {str(e)}"

def main():
    # 目标文件路径
    file_path = r"C:\file\lab1\629926cb814bc3f06828a39a8333d172_1_to_content"
    
    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return
    
    print("正在提取文档形状对象的内容...")
    content = extract_shapes_content(file_path)
    print("-" * 50)
    print("形状对象内容:")
    print(content)
    print("-" * 50)

if __name__ == "__main__":
    main()
