# 文件敏感内容检测工具

## 项目简介

文件敏感内容检测工具是一个用于扫描目录或文件中敏感信息的Python工具。它能够处理多种文件格式，提取文本内容，并根据配置的敏感词规则进行检测，最终生成详细的检测报告。

## 功能特点

- **多格式支持**：支持处理文本文件、Microsoft Office文档、PDF、图片、压缩文件等多种格式
- **敏感内容检测**：基于配置的敏感词和模式进行内容检测
- **多线程处理**：使用线程池并行处理多个文件，提高处理效率
- **实时监控**：在处理过程中实时显示进度和结果
- **多种导出格式**：支持将结果导出为JSON和Excel格式
- **容错机制**：针对各种异常情况设计了完善的容错机制
- **多种编码支持**：自动检测并处理多种文件编码

## 安装说明

### 依赖项

- Python 3.6+
- 第三方库：
  - yaml
  - python-magic
  - openpyxl
  - pandas
  - xlrd
  - markitdown

### 安装步骤

1. 克隆项目到本地：

```bash
git clone https://github.com/yourusername/sensitive-detector.git
cd sensitive-detector
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

### 基本用法

```bash
python main.py /path/to/directory
```

### 命令行参数

```
用法: main.py [-h] [--config CONFIG] [--output OUTPUT] [--chunk-size CHUNK_SIZE] [--workers WORKERS] path

文件敏感内容检测工具

位置参数:
  path                  要处理的文件或目录路径

可选参数:
  -h, --help            显示帮助信息
  --config CONFIG       敏感词配置文件路径 (默认: sensitive_config.yaml)
  --output OUTPUT       输出结果文件名前缀 (默认: results)
  --chunk-size CHUNK_SIZE
                        每批处理的文件数量 (默认: 1000)
  --workers WORKERS     最大工作线程数 (默认: CPU核心数的2倍)
```

### 敏感词配置

敏感词配置使用YAML格式，示例如下：

```yaml
security_marks:
  - "机密"
  - "绝密"
  - "confidential"
  - "仅内部使用"

sensitive_patterns:
  身份信息:
    keywords:
      - "身份证"
      - "护照"
    description: "个人身份信息"
  
  财务信息:
    keywords:
      - "银行账户"
      - "信用卡"
    description: "个人财务信息"

structured_patterns:
  "\\d{17}[0-9X]": 10  # 身份证号码模式
  "\\d{16,19}": 5      # 银行卡号模式

number_patterns:
  - "\\d{6}(\\d{8})\\d{3}[0-9X]"  # 身份证号码
```

## 输出结果

程序会生成以下输出文件：

1. `{output}_processing.csv`: 处理过程中的实时记录
2. `{output}.json`: JSON格式的详细结果
3. `{output}.xlsx`: Excel格式的摘要结果

## 核心组件

- `FileTypeDetector`: 文件类型检测
- `ContentExtractor`: 内容提取
- `SensitiveChecker`: 敏感内容检查
- `ResultExporter`: 结果导出
- `ResultMonitor`: 结果监控
- `FileProcessor`: 文件处理主类

## 高级特性

### 文件类型检测

系统使用python-magic库进行文件类型检测，支持以下文件类型：

- 文本文件：TXT, CSV, XML, HTML, JSON, YAML, MD
- 微软Office文档：DOC, DOCX, XLS, XLSX, PPT, PPTX
- 压缩文件：ZIP, RAR, 7Z, TAR, GZ, BZ2
- PDF文件
- 图片文件：JPG, JPEG, PNG, GIF, BMP, SVG, WEBP
- 音视频文件：MP3, MP4, AVI, MOV, WAV
- 其他二进制文件

### 性能优化

- 使用线程池并行处理文件
- 批量处理减少内存占用
- 缓存文件类型和大小减少IO操作
- 预处理阶段优化文件处理流程

## 日志和错误处理

系统日志存储在`sensitive_detector.log`文件中，包含详细的处理信息和错误记录。

## 注意事项

- 处理大型Excel文件可能需要较多内存
- 对于某些特殊格式的文件，可能需要安装额外的库
- 建议在处理大量文件前，先在小样本上测试性能和准确性

## 许可证

[添加适当的许可证信息]

## 联系方式

[添加联系方式]
