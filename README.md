# 禅道身份认证绕过漏洞利用工具

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="python">
  <img src="https://img.shields.io/badge/PyQt5-GUI-green.svg" alt="pyqt5">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS-lightgrey.svg" alt="platform">
</p>


## 📖 项目简介

本工具由 **hilyary** 开发，旨在为安全研究人员提供一个 **可视化复现环境**，用于学习与测试 **禅道身份认证绕过漏洞**。  
工具提供了 **跨平台支持**，Windows 用户可直接运行 `.exe`，macOS 用户可直接运行 `.dmg`。

⚠️ **仅限安全研究、内部测试与学习用途**，禁止用于非法渗透！  

---

## ✨ 功能特点

- 🔍 一键检测目标站点是否存在漏洞  
- 🌐 支持 HTTP / SOCKS5 代理，含认证模式  
- ➕ 快速添加用户（可自定义用户名/密码）  
- 🖥️ 跨平台：Windows（exe） & macOS（dmg） & Python 源码  
- 🎨 图形化界面（PyQt5），操作简单直观  

---

## 🖼️ 界面预览

### 综合信息

![screenshot1.png](/assets/screenshot1.png.png)

---

### 添加用户

![screenshot2](assets/image-20250903203220517.png)

---

### 设置代理

![screenshot3](assets/image-20250903203229516.png)

---

## 🚀 使用方法

### 方法一：直接运行（推荐）

- **Windows 用户**  
  双击运行：  

  ```
  禅道.exe
  ```

- **macOS 用户**  
  双击运行：  

  ```
  禅道利用工具_by_hilyary.dmg
  ```

---

### 方法二：源码运行

#### 1. 克隆项目

```bash
git clone https://github.com/hilyary/chandao-exp.git
cd chandao-exp
```

#### 2. 安装依赖

```bash
pip install -r requirements.txt
```

#### 3. 启动工具

```bash
python 禅道.py
```

---

## ⚠️ 免责声明

本工具仅限用于：

- ✅ 本地环境安全研究  
- ✅ 合法授权的测试  
- ✅ 学习与交流  

请勿将其用于 **任何未授权的渗透或攻击**，否则后果由使用者自行承担。  
作者 **hilyary** 不对工具的非法使用承担任何责任。  

---

## 🧑‍💻 作者 & 团队

- 作者：**hilyary**  
- 版本：v1.0  
- 项目地址：[https://github.com/hilyary/chandao-exp](https://github.com/hilyary/chandao-exp)  
