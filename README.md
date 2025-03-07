# Webshell 检测器使用指南
> webshell检测引擎开发中…… 代码后续发，正在研究下算法实现


## 已完成功能 ✓
- [x] 基础GO检测项目框架搭建
- [x] 配置文件管理
- [x] 基本的特征匹配检测：正则表达式匹配、YARA规则匹配
- [x] 简单的机器学习模型
- [x] 基础的文件扫描功能:手动、自动、定时
- [x] SQLite数据库存储


## 后续计划

1. 特征库增强

- [ ] 扩充YARA规则库，增加更多的WebShell特征识别规则
- [ ] 收集最新的WebShell样本，提取新的特征模式
- [ ] 增加对加密/混淆WebShell的检测能力
- [ ] 添加基于行为的检测规则(如文件操作、网络连接等)

2. 机器学习模型优化
- [ ] 扩充训练数据集，确保包含足够的正负样本
- [ ] 尝试其他机器学习算法(如XGBoost、LightGBM等)
- [ ] 增加特征维度，如:
  - 文件熵值
  - 字符频率分布
  - 代码结构特征
  - API调用序列
- [ ] 使用深度学习模型处理复杂特征

3. 检测引擎增强
- [ ] 实现多层检测机制:
  - 静态特征匹配
  - 动态行为分析 
  - 机器学习预测
  - 启发式规则检查
- [ ] 优化检测算法效率
- [ ] 添加沙箱执行环境


## 目标指标
- [ ] 检测率达到99%

- [ ] 误报率控制在1%以下

- [ ] 单文件扫描时间<1s

- [ ] 系统稳定运行>30天

## 1. 安装必要的依赖
```bash
# 安装 Go (如果还没安装)
sudo apt-get update
sudo apt-get install golang-go

# 安装 SQLite3
sudo apt-get install sqlite3

# 安装 PHP (用于行为分析)
sudo apt-get install php -y 

# 安装 strace (用于行为分析)
sudo apt-get install strace -y 
```

## 2. 创建项目目录并初始化
```bash
mkdir -p ~/webshell-detector
cd ~/webshell-detector
go mod init webshell-detector
go mod tidy
```

## 3. 安装项目依赖
```bash
go get github.com/mattn/go-sqlite3
go get github.com/fatih/color
go get github.com/fsnotify/fsnotify
go get gopkg.in/yaml.v3
go get github.com/sajari/regression
```

## 4. 创建必要的目录
```bash
mkdir -p data/signatures
mkdir -p data/models
mkdir -p configs
```

## 5. 创建一个基本的配置文件 configs/config.yaml
```yaml
scan:
  file_types:
    - .php
    - .jsp
    - .asp
    - .aspx
  exclude_dirs:
    - /var/www/html/cache
    - /var/www/html/uploads
  realtime:
    enabled: false
    max_concurrency: 5
  schedule:
    enabled: false

detection:
  feature_matching:
    enabled: true
    min_confidence: 0.6
  behavior_analysis:
    enabled: true
    timeout: 30
  machine_learning:
    enabled: true
    threshold: 0.8

alert:
  threshold:
    high_risk: 80
    medium_risk: 60
    low_risk: 40
  email:
    enabled: false
  sms:
    enabled: false

storage:
  database:
    type: sqlite
    path: data/webshell-detector.db
  history:
    retention_days: 90
    max_records: 1000000

signature_path: "data/signatures/signature.db"
model_path: "data/models/rf_model.bin"
```

编译项目
```
cd webshell-detector
go build -o webshell-detector cmd/main.go
```

## 7. 测试用的 webshell 文件（仅用于测试）
```bash
cat > test_webshell.php << 'EOF'
<?php
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    system($cmd);
}
?>
<form method="post">
    <input type="text" name="cmd">
    <input type="submit" value="Execute">
</form>
EOF
```

## 8. 测试单个文件
```bash
./webshell-detector -mode manual -file /
```

## 9. 启动实时监控
```bash
./webshell-detector -mode realtime
```

## 10. 启动定时扫描
```bash
./webshell-detector -mode scheduled
```

## 11. 支持的扫描模式
- `manual`：手动扫描单个文件
- `realtime`：实时监控文件系统变化
- `scheduled`：按计划定时扫描

## 12. 关于规则导入
### 创建初始化签名 SQL 文件
```bash
cat > init_signatures.sql << 'EOF'
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    weight REAL NOT NULL,
    category TEXT,
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    update_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO signatures (pattern, type, description, weight, category) VALUES
('system\s*\(', 'regex', 'System command execution', 0.8, 'command_execution'),
('eval\s*\(', 'regex', 'Dynamic code execution', 0.9, 'code_execution'),
('shell_exec', 'string', 'Shell command execution', 0.8, 'command_execution'),
('base64_decode', 'string', 'Base64 decode usage', 0.6, 'encoding'),
('cmd', 'string', 'Command parameter', 0.5, 'parameter');
EOF
```

### 创建并执行 SQL 文件
```bash
# 确保目录存在
mkdir -p data/signatures

# 创建新的数据库并执行 SQL 文件
sqlite3 data/signatures/signature.db ".read init_signatures.sql"
```

### 查看表结构和插入的数据
```bash
# 查看表结构
sqlite3 data/signatures/signature.db ".schema signatures"

# 查看插入的数据
sqlite3 data/signatures/signature.db "SELECT * FROM signatures;"
```

## 13. 关于模型训练：采用 python+go+sklearn 训练
```bash
cd tools
python train_model.py
```

## 14. 效果示例
```
Starting detection process...
1. Running feature matching analysis...
2025/03/01 03:33:55 |=====特征匹配检测
2. Running behavior analysis...
3. Running machine learning analysis...
Detection process completed.

========== Webshell Detection Report ==========

1. Feature Matching Analysis:
   Matched Features:
File Path:    training_data/webshell/php/webshell.php
Risk Level:   MEDIUM
Is Webshell:  Yes
Total Score:  51.83
   Score:     0.50
   - Command parameter

2. Behavior Analysis:
   Detected Behaviors:
   Score:  55.00
   - Attempted to establish network connection
   - Attempted to execute external commands

3. Machine Learning Analysis:

============================================
   Score:  100.00

Scan completed in 237.632085ms
```
