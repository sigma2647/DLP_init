# 【最新更新】
# v2.2
# 1. 设置了防过拟合；
# 2. 增加同义词转换辨认（字典：chinese_synonyms.txt）。
#==================
# 【历史更新】
# v2.1
# 1. 增加了日志；
# 2. 中文结合jieba分词，英文结合nltk单词识别（中文特征2字以上，英文不能是一个字母）。
#------------------
# v2.0
# 1. 结合了sensitive_dict.yaml辅助bert模型

import warnings
from datetime import datetime, time
warnings.filterwarnings("ignore", category=UserWarning)
import platform
import jieba
import nltk
import yaml
import re
import sqlite3
import pandas as pd
import numpy as np
from langdetect import detect
from nltk.tokenize import word_tokenize
from sklearn.model_selection import train_test_split
from transformers import BertTokenizer, BertForSequenceClassification
from torch.utils.data import DataLoader, Dataset
import torch
from tqdm import tqdm
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import time
import os


class TrainingLogger:
    """训练日志记录器"""

    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # 创建以时间戳命名的日志文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(log_dir, f"training_{timestamp}.log")

        # 初始化日志文件头
        self._write_log(f"Training Log - {timestamp}\n{'=' * 40}\n")

    def _write_log(self, message, level="INFO"):
        """写入日志的底层方法"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(log_entry)

    def log_parameters(self, params):
        """记录训练参数"""
        param_str = "\n".join([f"- {k}: {v}" for k, v in params.items()])
        self._write_log(f"Training Parameters:\n{param_str}\n{'=' * 40}")

    def log_epoch_start(self, epoch, phase="train"):
        """记录阶段开始"""
        self._write_log(f"\n{'=' * 40}")
        self.start_time = time.time()
        self._write_log(f"Epoch {epoch} {phase.upper()} Phase Started")

    def log_epoch_end(self, epoch, phase="train", metrics=None):
        """记录阶段结束"""
        duration = time.time() - self.start_time
        log_msg = f"Epoch {epoch} {phase.upper()} Phase Completed - Duration: {duration:.2f}s"

        if metrics:
            metrics_str = "\n".join([f"- {k}: {v:.4f}" for k, v in metrics.items()])
            log_msg += f"\n{phase.upper()} Metrics:\n{metrics_str}"

        self._write_log(log_msg + f"\n{'=' * 40}")

    def log_classification_report(self, report_dict):
        """记录分类报告"""
        report_str = "\nClassification Report:\n"
        report_str += f"{'Class':<10}{'Precision':<10}{'Recall':<10}{'F1-Score':<10}{'Support':<10}\n"

        # 添加每个类别的指标
        for label in ["非敏感", "敏感"]:
            if label in report_dict:
                metrics = report_dict[label]
                report_str += (
                    f"{label:<10}"
                    f"{metrics['precision']:<10.2f}"
                    f"{metrics['recall']:<10.2f}"
                    f"{metrics['f1-score']:<10.2f}"
                    f"{metrics['support']:<10}\n"
                )

        # 添加平均指标
        for avg_type in ['macro avg', 'weighted avg']:
            if avg_type in report_dict:
                metrics = report_dict[avg_type]
                report_str += (
                    f"{avg_type:<10}"
                    f"{metrics['precision']:<10.2f}"
                    f"{metrics['recall']:<10.2f}"
                    f"{metrics['f1-score']:<10.2f}"
                    f"{metrics['support']:<10}\n"
                )

        # 添加准确率
        if 'accuracy' in report_dict:
            report_str += f"\nAccuracy: {report_dict['accuracy']:.2f}\n"

        self._write_log(report_str)

    def log_confusion_matrix(self, matrix):
        """记录混淆矩阵"""
        matrix_str = "\nConfusion Matrix:\n"
        matrix_str += "          Predicted\n"
        matrix_str += "          Non-Sensitive  Sensitive\n"
        matrix_str += "Actual\n"
        matrix_str += f"Non-Sensitive  {matrix[0][0]:<12}  {matrix[0][1]}\n"
        matrix_str += f"Sensitive      {matrix[1][0]:<12}  {matrix[1][1]}\n"
        self._write_log(matrix_str)

    def log_best_model(self, epoch, test_loss, test_accuracy, model_path):
        """记录最佳模型信息"""
        summary = (
                "\nBest Model Summary:\n"
                f"- Epoch: {epoch}\n"
                f"- Test Loss: {test_loss:.4f}\n"
                f"- Test Accuracy: {test_accuracy:.2%}\n"
                f"- Saved Path: {os.path.abspath(model_path)}\n"
                "=" * 40
        )
        self._write_log(summary)

class SensitiveContentDataset(Dataset):
    """支持多语言处理的自定义数据集类"""

    def __init__(self, texts, labels, tokenizer, en_phrase_rules, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.en_phrase_rules = en_phrase_rules

        # 加载中文同义词词典
        self.chinese_synonyms = self._load_chinese_synonyms('chinese_synonyms.txt')

    def _load_chinese_synonyms(self, file_path):
        """加载中文同义词词典"""
        synonyms = {}
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    word, *syns = line.strip().split()
                    synonyms[word] = np.random.choice(syns) if syns else word
        return synonyms

    def __len__(self):
        return len(self.texts)

    def _preprocess_text(self, text):
        """多语言文本预处理"""
        try:
            lang = detect(text)
        except:
            lang = 'en'

        # 中文处理
        if lang in ['zh-cn', 'zh-tw']:
            # 中文处理
            if lang in ['zh-cn', 'zh-tw']:
                text = ' '.join(jieba.lcut(text))
            else:
                text = ' '.join(word_tokenize(text))

            # 数据增强
            if np.random.rand() < 0.3:  # 30%概率应用增强
                if np.random.rand() < 0.5:
                    text = self.random_deletion(text)
                else:
                    text = self.synonym_replacement(text, lang)

                words = text.split()
                new_words = [self.get_synonyms(word, lang) for word in words]
                text = ' '.join(new_words)

            return text

        # 英文处理
        processed_text = text
        for pattern, replacement in self.en_phrase_rules:
            processed_text = re.sub(pattern, replacement, processed_text)
        return ' '.join(word_tokenize(processed_text))

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]

        # 预处理文本
        processed_text = self._preprocess_text(text)

        encoding = self.tokenizer.encode_plus(
            processed_text,
            add_special_tokens=True,
            max_length=self.max_length,
            truncation=True,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt'
        )
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'label': torch.tensor(label, dtype=torch.long)
        }

    def random_deletion(self, text, p=0.2):
        """随机删除单词"""
        words = text.split()
        if len(words) == 1:
            return text
        remaining = [word for word in words if np.random.rand() > p]
        return ' '.join(remaining) if remaining else words[0]

    def get_synonyms(self, word, lang='en'):
        """获取单词的同义词"""
        if lang in ['zh-cn', 'zh-tw']:
            # 中文同义词
            return self.chinese_synonyms.get(word, word)
        else:
            # 英文同义词（使用NLTK的WordNet）
            from nltk.corpus import wordnet
            synonyms = set()
            for syn in wordnet.synsets(word):
                for lemma in syn.lemmas():
                    synonyms.add(lemma.name())
            if synonyms:
                return np.random.choice(list(synonyms))
            return word

    def synonym_replacement(self, text, lang='en'):
        """同义词替换"""
        if lang in ['zh-cn', 'zh-tw']:
            # 使用jieba分词
            words = jieba.lcut(text)
            # 替换同义词（需实现get_synonyms方法）
            new_words = [self.get_synonyms(word, lang) for word in words]
            return ' '.join(new_words)
        else:
            # 英文同义词替换
            words = word_tokenize(text)
            new_words = [self.get_synonyms(word, lang) for word in words]
            return ' '.join(new_words)

class SensitiveContentModel:
    def __init__(self,
                 model_name='bert-base-multilingual-cased',
                 max_length=128,
                 batch_size=16,
                 epochs=3,
                 learning_rate=2e-5,
                 patience=3,
                 weight_decay=0.01,  # L2正则化
                 dropout_rate=0.2,  # Dropout率
                 dict_path='sensitive_dict.yaml'):

        # 初始化设备
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")

        # 在创建数据集时传递同义词词典
        self.dataset = None  # 稍后在创建数据集时初始化

        # 添加正则化和Dropout参数
        self.weight_decay = weight_decay
        self.dropout_rate = dropout_rate

        # 初始化模型时添加Dropout
        self.model = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2,
            hidden_dropout_prob=self.dropout_rate,  # 隐藏层Dropout
            attention_probs_dropout_prob=self.dropout_rate,  # 注意力Dropout
            classifier_dropout=self.dropout_rate  # 分类器Dropout
        ).to(self.device)

        # 初始化配置参数
        self.model_name = model_name
        self.max_length = max_length
        self.batch_size = batch_size
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.patience = patience
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.best_test_loss = float('inf')  # 跟踪最佳测试损失

        # 添加日志记录器
        self.logger = TrainingLogger()

        # 记录初始化参数
        params = {
            "model_name": model_name,
            "max_length": max_length,
            "batch_size": batch_size,
            "epochs": epochs,
            "learning_rate": learning_rate,
            "patience": patience,
            "dict_path": dict_path
        }
        self.logger.log_parameters(params)

        # 加载敏感词词典
        with open(dict_path, 'r', encoding='utf-8') as f:
            self.sensitive_dict = yaml.safe_load(f)

        # 初始化分词器
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        self._enhance_tokenizer()

        # 初始化模型
        self.model = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2
        ).to(self.device)

        # 配置jieba分词器
        jieba.load_userdict(dict_path)
        for word in self.sensitive_dict.get('chinese', []):
            jieba.suggest_freq(word, tune=True)

        # Windows系统优化
        if platform.system() == 'Windows':
            self._windows_optimize()

        self.model = BertForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2
        ).to(self.device)  # 将模型移动到设备

    def _windows_optimize(self):
        """Windows系统专用优化"""
        test_text = ' '.join(self.sensitive_dict.get('chinese', []))
        list(jieba.cut(test_text))
        print("Windows optimization: Dictionary preloaded")

    def _enhance_tokenizer(self):
        """增强分词器"""
        orig_tokenize = self.tokenizer.tokenize

        def hybrid_tokenize(text, *args, **kwargs):
            try:
                lang = detect(text)
            except:
                lang = 'en'

            if lang in ['zh-cn', 'zh-tw']:
                words = jieba.lcut(text)
                processed_text = ' '.join(words)
            else:
                processed_text = text
                for pattern, replacement in self.sensitive_dict.get('english_phrases', []):
                    processed_text = re.sub(pattern, replacement, processed_text)

            return orig_tokenize(processed_text, *args, **kwargs)

        self.tokenizer.tokenize = hybrid_tokenize

    def load_data_from_db(self, db_path, table_name):
        """从数据库加载数据"""
        try:
            conn = sqlite3.connect(db_path)
            query = f"SELECT content, is_sensitive FROM {table_name}"
            data = pd.read_sql_query(query, conn)
            conn.close()
            return data
        except Exception as e:
            print(f"数据加载失败：{str(e)}")
            return None

    def augment_inputs(self, inputs, p=0.3):
        """对输入数据进行增强"""
        input_ids = inputs['input_ids']
        attention_mask = inputs['attention_mask']

        # 随机删除
        if np.random.rand() < p:
            input_ids, attention_mask = self._random_deletion(input_ids, attention_mask)

        # 同义词替换
        if np.random.rand() < p:
            input_ids = self._synonym_replacement(input_ids)

        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask
        }

    def _random_deletion(self, input_ids, attention_mask, p=0.2):
        """随机删除token"""
        mask = (torch.rand(input_ids.shape) > p).to(self.device)  # 保留概率
        input_ids = input_ids * mask.long()  # 删除部分token
        attention_mask = attention_mask * mask.long()
        return input_ids, attention_mask

    def _synonym_replacement(self, input_ids):
        """同义词替换"""
        tokens = self.tokenizer.convert_ids_to_tokens(input_ids[0].tolist())
        new_tokens = []
        for token in tokens:
            if token in ['[CLS]', '[SEP]', '[PAD]']:
                new_tokens.append(token)
            else:
                # 使用数据集中的同义词词典
                new_token = self.dataset.get_synonyms(token, lang='zh-cn')
                new_tokens.append(new_token)
        new_input_ids = self.tokenizer.convert_tokens_to_ids(new_tokens)
        return torch.tensor([new_input_ids], device=self.device)

    def get_synonym(self, token):
        """获取token的同义词"""
        # 中文同义词（需提前加载同义词词典）
        if hasattr(self, 'chinese_synonyms'):
            return self.chinese_synonyms.get(token, token)

        # 英文同义词（使用NLTK的WordNet）
        from nltk.corpus import wordnet
        synonyms = set()
        for syn in wordnet.synsets(token):
            for lemma in syn.lemmas():
                synonyms.add(lemma.name())
        if synonyms:
            return np.random.choice(list(synonyms))
        return token

    def features_preprocess(self, data):
        """数据预处理"""
        def _process_text(text):
            try:
                lang = detect(text)
            except:
                lang = 'en'

            if lang in ['zh-cn', 'zh-tw']:
                return ' '.join(jieba.lcut(text))

            processed_text = text
            for pattern, replacement in self.sensitive_dict.get('english_phrases', []):
                processed_text = re.sub(pattern, replacement, processed_text)
            return ' '.join(word_tokenize(processed_text))

        X = data['content'].apply(_process_text).tolist()
        y = data['is_sensitive'].tolist()
        print(X,y)
        return X, y

    def create_data_loader(self, X, y):
        """创建数据加载器"""
        self.dataset = SensitiveContentDataset(
        X, y,
        self.tokenizer,
        self.sensitive_dict.get('english_phrases', []),
        self.max_length
    )
        return DataLoader(self.dataset, batch_size=self.batch_size, shuffle=True)

    def train(self, train_loader, test_loader):
        """训练流程"""

        # 使用AdamW优化器，添加L2正则化
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay  # L2正则化
        )

        # 添加学习率调度器
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer,
            mode='min',  # 监控验证损失
            factor=0.5,  # 学习率衰减因子
            patience=2,  # 连续2轮验证损失未改善时衰减
            verbose=True
        )

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.learning_rate)
        train_losses = []
        test_losses = []
        test_accuracies = []
        best_model_path = 'best_model.pth'

        for epoch in range(self.epochs):
            # 记录epoch开始
            self.logger.log_epoch_start(epoch, "train")
            print(f"\nEpoch {epoch + 1}/{self.epochs}")

            # 训练阶段
            self.model.train()
            total_train_loss = 0
            progress_bar = tqdm(train_loader, desc="Training", leave=False)

            for batch in progress_bar:
                inputs = {k: v.to(self.device) for k, v in batch.items() if k != 'label'}
                labels = batch['label'].to(self.device)

                # 前向传播
                outputs = self.model(**inputs, labels=labels)
                loss = outputs.loss

                # 梯度裁剪
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                # 反向传播
                loss.backward()
                optimizer.step()
                optimizer.zero_grad()

                total_train_loss += loss.item()
                progress_bar.set_postfix({'loss': loss.item()})

            # 计算平均训练损失
            avg_train_loss = total_train_loss / len(train_loader)
            train_losses.append(avg_train_loss)

            # 记录训练结束
            self.logger.log_epoch_end(epoch, "train",
                                      {"Train Loss": avg_train_loss})

            # 测试阶段
            # 记录测试开始
            self.logger.log_epoch_start(epoch, "test")
            avg_test_loss, test_accuracy = self.evaluate(test_loader,epoch)
            self.logger.log_epoch_end(epoch, "test",
                                      {"Test Loss": avg_test_loss,
                                       "Test Accuracy": test_accuracy})
            test_losses.append(avg_test_loss)
            test_accuracies.append(test_accuracy)

            # 保存最佳模型
            if avg_test_loss < self.best_test_loss:
                self.best_test_loss = avg_test_loss
                no_improve = 0
                # 保存最佳模型
                torch.save(self.model.state_dict(), 'best_model.pth')
                print(f"\n保存最佳模型，测试损失：{avg_test_loss:.4f}，准确率：{test_accuracy:.2%}")
            else:
                no_improve += 1
                if no_improve >= self.patience:
                    print("Early stopping triggered!")
                    break

            # 更新学习率
            scheduler.step(avg_test_loss)

            # 打印统计信息
            print(f"Epoch {epoch + 1} 统计:")
            print(f"训练损失: {avg_train_loss:.4f} | 测试损失: {avg_test_loss:.4f} | 测试准确率: {test_accuracy:.2%}")

            # Early Stopping
            if (epoch - np.argmin(test_losses)) >= self.patience:
                print("\nEarly stopping triggered!")
                break

        # 可视化训练过程
        self._plot_training_curves(train_losses, test_losses, test_accuracies)
        print(f"\n最佳模型已保存至：{os.path.abspath(best_model_path)}")

    def evaluate(self, data_loader,epoch):
        """模型评估，输出损失值、准确度、分类报告和混淆矩阵"""
        self.model.eval()
        total_loss = 0
        correct_predictions = 0
        total_samples = 0

        # 用于存储所有预测结果和真实标签
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in tqdm(data_loader,desc="Evaluating"):
                # 将数据移动到设备（GPU或CPU）
                inputs = {
                    'input_ids': batch['input_ids'].to(self.device),
                    'attention_mask': batch['attention_mask'].to(self.device)
                }
                labels = batch['label'].to(self.device)

                # 前向传播
                outputs = self.model(**inputs, labels=labels)
                loss = outputs.loss
                total_loss += loss.item()

                # 计算预测结果
                preds = torch.argmax(outputs.logits, dim=1)
                correct_predictions += torch.sum(preds == labels).item()
                total_samples += labels.size(0)

                # 保存预测结果和真实标签
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

                # 计算平均损失和准确度
            avg_loss = total_loss / len(data_loader)
            accuracy = correct_predictions / total_samples

        # 输出损失值和准确度
        print(f"测试集损失: {avg_loss:.4f}")
        print(f"测试集准确度: {accuracy:.2%}")

        # 输出分类报告
        print("\n分类报告:")
        print(classification_report(all_labels, all_preds, target_names=["非敏感", "敏感"]))

        # 输出混淆矩阵
        cm = confusion_matrix(all_labels, all_preds)
        print("\n混淆矩阵:")
        print(cm)

        # 可视化混淆矩阵
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["非敏感", "敏感"],
                    yticklabels=["非敏感", "敏感"])
        plt.xlabel("预测标签")
        plt.ylabel("真实标签")
        plt.title("混淆矩阵")
        # plt.show()

        # 生成分类报告字典
        report_dict = classification_report(
            all_labels, all_preds,
            target_names=["非敏感", "敏感"],
            output_dict=True
        )

        # 记录分类报告和混淆矩阵
        self.logger.log_classification_report(report_dict)
        self.logger.log_confusion_matrix(cm)

        return avg_loss, accuracy

    def _plot_training_curves(self, train_losses, test_losses, test_accuracies):
        """绘制整体的训练曲线"""
        plt.figure(figsize=(15, 5))

        # 损失曲线
        plt.subplot(1, 2, 1)
        plt.plot(train_losses, label='Training Loss')
        plt.plot(test_losses, label='testidation Loss')
        plt.xlabel('Epochs')
        plt.ylabel('Loss')
        plt.title('Training and testidation Loss')
        plt.legend()

        # 准确率曲线
        plt.subplot(1, 2, 2)
        plt.plot(test_accuracies, label='testidation Accuracy', color='green')
        plt.xlabel('Epochs')
        plt.ylabel('Accuracy')
        plt.title('testidation Accuracy')
        plt.legend()

        plt.tight_layout()
        plt.show()

    def _analyze_top_features(self, texts, preds, n=10):
        """分析分类依据TOP10，结合BERT模型的注意力权重和YAML里的敏感词"""
        print("\n=== 分类依据TOP10分析 ===")

        sensitive_texts = [text for text, pred in zip(texts, preds) if pred == 1]
        keyword_counts = {}

        # 统计预设敏感词（过滤单字）
        for text in sensitive_texts:
            # 中文词统计（仅长度≥2）
            for keyword in self.sensitive_dict.get('chinese', []):
                if len(keyword) >= 2 and keyword in text:
                    keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1

            # 英文模式匹配（检查实际匹配文本长度）
            for pattern, _ in self.sensitive_dict.get('english_phrases', []):
                matches = re.finditer(pattern, text, flags=re.IGNORECASE)
                for match in matches:
                    matched_text = match.group()
                    if len(matched_text) >= 2:
                        keyword_counts[pattern] = keyword_counts.get(pattern, 0) + 1

        # 获取BERT注意力权重（过滤单字符token）
        self.model.eval()
        dataset = SensitiveContentDataset(texts, [0] * len(texts), self.tokenizer,
                                          self.sensitive_dict.get('english_phrases', []),
                                          self.max_length)

        with torch.no_grad():
            for text in sensitive_texts:
                processed_text = dataset._preprocess_text(text)
                encoding = self.tokenizer.encode_plus(
                    processed_text,
                    max_length=self.max_length,
                    truncation=True,
                    padding='max_length',
                    return_tensors='pt'
                ).to(self.device)

                outputs = self.model(**encoding, output_attentions=True)
                attentions = outputs.attentions[-1].squeeze(0)
                avg_attention = attentions.mean(dim=0)

                tokens = self.tokenizer.convert_ids_to_tokens(encoding['input_ids'].squeeze().tolist())
                for token, weight in zip(tokens, avg_attention.mean(dim=0).tolist()):
                    if token in ['[CLS]', '[SEP]', '[PAD]']:
                        continue
                    if len(token) >= 2:  # 过滤单字符
                        keyword_counts[token] = keyword_counts.get(token, 0) + weight

        # 最终过滤并排序
        sorted_keywords = sorted(
            [(k, v) for k, v in keyword_counts.items() if len(k.strip()) >= 2],
            key=lambda x: x[1],
            reverse=True
        )[:n]

        print(f"\n敏感内容TOP{n}分类依据:")
        for i, (keyword, weight) in enumerate(sorted_keywords, 1):
            print(f"{i}. {keyword} (权重/频率: {weight:.4f})")



    def main(self,n):
        """主流程"""
        data = self.load_data_from_db('new_data.db', 'files')
        if data is None:
            return

        # 打印原始数据量
        print(f"原始数据集数量: {len(data)}")

        X, y = self.features_preprocess(data)
        # 打印预处理后的有效数据量
        print(f"预处理后有效样本数: {len(X)}")

        # 划分训练测试集
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.3,
            random_state=42
        )
        # print(f"训练集数量: {len(X_train)}")
        # print(f"测试集数量: {len(X_test)}")

        # 创建数据加载器
        train_loader = self.create_data_loader(X_train, y_train)
        test_loader = self.create_data_loader(X_test, y_test)

        # 测试加载器数据量
        total_train_samples = len(train_loader.dataset)
        total_test_samples = len(test_loader.dataset)
        print(f"训练加载器总样本: {total_train_samples}")
        print(f"测试加载器总样本: {total_test_samples}")

        # 训练模型
        self.train(train_loader, test_loader)

        # 分析分类依据TOP n
        self._analyze_top_features(X_test, y_test,n)  # X_test 是测试集的原始文本


if __name__ == '__main__':
    # 配置NLTK数据路径
    nltk_data_path = os.path.join(os.getcwd(), 'nltk_data')
    nltk.data.path.append(nltk_data_path)

    # 设置plt图片文字格式
    plt.rcParams['font.family'] = 'SimHei'  # 设置全局字体
    plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

    # 初始化并运行模型
    model = SensitiveContentModel(
        model_name='bert-base-multilingual-cased',
        max_length=256,
        batch_size=8,
        epochs=10,
        learning_rate=2e-5,  # 如果学习率设置得过高，模型参数在更新时可能会变得不稳定，导致损失值爆炸（变得非常大）或直接变为 NaN。  3e-5就会变成nan
        patience=5,
        weight_decay=0.01,  # L2正则化
        dropout_rate=0.2,  # Dropout率
        dict_path='sensitive_dict.yaml'
    )
    model.main(n=15)




