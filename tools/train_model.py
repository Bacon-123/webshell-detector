import os
import pickle
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def extract_features(file_path):
    """提取文件特征"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        features = []
        
        # 特征1: 文件大小
        features.append(len(content))
        
        # 特征2: 危险函数的数量
        dangerous_funcs = ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru(']
        count = sum(content.count(func) for func in dangerous_funcs)
        features.append(count)
        
        # 特征3: base64编码字符串的数量
        features.append(content.count('base64_decode'))
        
        # 特征4: $_POST, $_GET 等超全局变量的使用数量
        super_globals = ['$_POST', '$_GET', '$_REQUEST', '$_SERVER']
        count = sum(content.count(sg) for sg in super_globals)
        features.append(count)
        
        # 特征5: 文件权限相关函数的使用数量
        perm_funcs = ['chmod(', 'chown(', 'fopen(', 'file_put_contents(']
        count = sum(content.count(func) for func in perm_funcs)
        features.append(count)
        
        return features
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def collect_samples(normal_dir, webshell_dir):
    """收集训练样本"""
    X = []  # 特征
    y = []  # 标签
    
    # 收集正常文件样本
    for root, _, files in os.walk(normal_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                features = extract_features(file_path)
                if features:
                    X.append(features)
                    y.append(0)  # 正常文件标记为0
    
    # 收集webshell样本
    for root, _, files in os.walk(webshell_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                features = extract_features(file_path)
                if features:
                    X.append(features)
                    y.append(1)  # webshell文件标记为1
    
    return np.array(X), np.array(y)

def save_model_for_go(model, feature_weights, path):
    """保存一个简化的模型格式供 Go 程序使用"""
    model_data = {
        'weights': feature_weights.tolist(),  # 转换为普通列表
        'threshold': 0.5,
        'feature_count': len(feature_weights)
    }
    
    with open(path, 'w') as f:  # 使用文本模式打开
        json.dump(model_data, f, indent=2)

def main():
    # 训练数据目录
    normal_dir = "training_data/normal"
    webshell_dir = "training_data/webshell"
    
    # 确保输出目录存在
    os.makedirs("data/models", exist_ok=True)
    
    # 收集样本
    print("Collecting samples...")
    X, y = collect_samples(normal_dir, webshell_dir)
    
    if len(X) == 0:
        print("No samples found!")
        return
    
    # 分割训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # 创建并训练随机森林模型
    print("Training model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    model.fit(X_train, y_train)
    
    # 评估模型
    print("\nModel Evaluation:")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # 获取特征权重
    feature_weights = model.feature_importances_
    
    # 保存简化的模型
    model_path = "data/models/rf_model.bin"
    save_model_for_go(model, feature_weights, model_path)
    
    print(f"Model saved to {model_path}")
    
    # 特征重要性
    print("\nFeature Importance:")
    feature_names = [
        "File Size",
        "Dangerous Functions",
        "Base64 Usage",
        "Superglobals",
        "File Operations"
    ]
    for name, importance in zip(feature_names, model.feature_importances_):
        print(f"{name}: {importance:.4f}")

if __name__ == "__main__":
    main()