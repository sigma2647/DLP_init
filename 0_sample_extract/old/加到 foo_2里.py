from xml.etree import ElementTree
import html
import sqlite3
import re

##### 数据库字段content初步格式化 ######
class format_DBcontent:
    def process_content(self, content, file_type):
        """根据文件类型处理内容"""
        if not content:
            return ""

        # XML处理（application/zip类型）
        if file_type == "application/zip":
            return self._process_xml(content)

        # 其他类型按CSS处理
        return self._process_css(content)

    def _process_xml(self, text):
        """处理XML内容：移除标签并提取文本"""
        try:
            # 尝试解析XML
            root = ElementTree.fromstring(text)
            elements = [elem.text.strip() for elem in root.iter() if elem.text]
            cleaned = " ".join(elements)
        except ElementTree.ParseError:
            # 解析失败时使用正则清理
            cleaned = re.sub(r"<[^>]+>", "", text)

        # 处理HTML转义字符并最终清理
        return self._final_clean(html.unescape(cleaned))

    def _process_css(self, text):
        """处理CSS内容：移除注释和特殊结构"""
        # 移除CSS注释
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        # 移除URL引用
        text = re.sub(r"url$[^)]*$", "", text, flags=re.IGNORECASE)
        # 移除CSS变量
        text = re.sub(r"var$--[^)]*$", "", text)
        return self._final_clean(text)

    def _final_clean(self, text):
        """最终清理：保留有效的中英文词汇"""
        # 转换为小写
        text = text.lower()
        # 匹配中文汉字和基本拉丁字母
        words = re.findall(r"[\u4e00-\u9fa5a-zA-Z]+", text)
        return " ".join(words).strip()

    def process_database(self, source_db, target_db):
        """处理数据库迁移"""
        try:
            # 数据库连接
            src_conn = sqlite3.connect(source_db)
            src_cur = src_conn.cursor()
            dst_conn = sqlite3.connect(target_db)
            dst_cur = dst_conn.cursor()

            # 复制表结构
            src_cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='files'")
            dst_cur.execute(src_cur.fetchone()[0])

            # 获取字段索引
            src_cur.execute("PRAGMA table_info(files)")
            columns = [col[1] for col in src_cur.fetchall()]
            content_idx = columns.index("content")
            type_idx = columns.index("file_type")

            # 批量处理数据
            src_cur.execute("SELECT * FROM files")
            while True:
                rows = src_cur.fetchmany(1000)
                if not rows:
                    break

                processed = []
                for row in rows:
                    row = list(row)
                    content = row[content_idx]
                    file_type = row[type_idx]

                    # 处理内容
                    row[content_idx] = self.process_content(content, file_type) if content else ""
                    processed.append(row)

                # 批量插入
                dst_cur.executemany(
                    f"INSERT INTO files VALUES ({','.join(['?']*len(columns))})",
                    processed
                )
                dst_conn.commit()

            print(f"数据库处理完成：{target_db}")

        except Exception as e:
            print(f"处理失败：{str(e)}")
            dst_conn.rollback()
        finally:
            src_conn.close()
            dst_conn.close()



if __name__ == '__main__':
    # 敏感文件位置
    #path_directory = r"D:\PyCharm Community Edition 2024.3.1.1\my_program\西湖创新项目\样本\敏感文件/"
    path_directory = input("检测的文件位置（如：D:\样本\敏感文件/）：")
    S_or_R = int(input("敏感文件为1，常规文件标记为0。当前文件标记为："))
    #
    # # 将数据最终导入到db中
    db_info.create_db_and_save_data(path_directory,S_or_R)

    ###### 数据库content内容初步格式化 ######
    fdb = format_DBcontent()
    fdb.process_database('data.db', 'new_data.db')