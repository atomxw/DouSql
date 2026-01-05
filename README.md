[![GitHub release (latest by date)](https://img.shields.io/github/v/release/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/darkfiv/DouSql?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/stargazers)
[![GitHub downloads](https://img.shields.io/github/downloads/darkfiv/DouSql/total?style=flat-square&logo=github)](https://github.com/darkfiv/DouSql/releases)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2024.6+-orange?style=flat-square&logo=portswigger)](https://portswigger.net/burp)


## 插件简介

**DouSql** 是基于Xia Sql二次开发的高度自定义化SQL注入检测插件，专为安全研究人员和渗透测试工程师打造。

## 主要功能

### 核心检测功能
- **多种SQL注入检测**：支持报错注入、时间盲注、布尔盲注等多种检测方式
- **智能payload管理**：内置多种payload组，支持自定义payload配置
- **丰富的默认字典**：包含18种常用SQL注入payload，涵盖时间盲注、布尔盲注、报错注入等
- **实时响应分析**：自动分析响应长度、时间、状态码等关键指标
- **全面的报错信息识别**：内置33种数据库和框架的错误信息模式，支持MySQL、Oracle、PostgreSQL、SQL Server、SQLite等
- **增强JSON处理**：使用Burp Suite内置API处理复杂嵌套JSON结构，支持任意深度的对象、数组和混合数据类型


### 高级配置选项
- **参数过滤系统**：支持白名单/黑名单模式，精确控制测试范围
- **URL黑名单过滤**：可配置黑名单URL，跳过不需要测试的路径
- **静态文件过滤**：自动跳过图片、样式、脚本等静态资源文件（支持30+种文件类型）
- **响应时间阈值**：可自定义时间盲注检测阈值
- **长度差异阈值**：可配置响应长度差异检测敏感度
- **自定义延时发包**：支持固定延时和随机延时，可配置延时区间（默认1-5秒）
- **自定义追加参数**：支持为请求自动追加多个指定参数，兼容URL、POST、JSON等格式
- **智能参数测试控制**：追加参数可选择是否参与payload测试，提供灵活的测试策略

### 最新功能亮点
- **完全修复中文参数编码问题**：支持UTF-8、GBK、GB2312等多种编码格式
- **智能编码检测与修复**：自动识别并修复参数传递过程中的编码损坏
- **增强JSON处理能力**：完美支持复杂嵌套JSON结构的中文参数
- **优化默认payload**：更新18个高质量SQL注入检测payload
- **payload管理优化**：分离保存和加载功能，操作更直观
- **自定义延时发包**：支持三种延时模式，可配置固定或随机延时，避免WAF检测
- **智能追加参数**：支持URL、POST、JSON三种格式的多参数自动追加，每个参数可独立控制测试开关

### 用户界面特性
- **双面板设计**：左侧显示扫描结果，右侧显示参数测试详情
- **实时状态更新**：支持报错标记(err)、时间超时标记(time)等状态显示
- **配置持久化**：所有配置自动保存，重启后自动恢复
- **Windows系统优化**：针对Windows系统进行UI布局优化，确保所有按钮和组件完整显示

### 工具集成
- **智能右键菜单**：支持payload组选择的右键菜单，可选择使用当前组或指定特定payload组进行测试
- **选择性监控**：默认只监控Proxy和Repeater的流量，需要手动启用对应的监控选项
- **自动检测**：通过右键菜单发送的请求会自动进行检测
- **多格式参数支持**：支持URL参数、POST参数、JSON参数、XML参数、Cookie参数等
- **灵活测试策略**：可根据不同场景选择合适的payload组，如时间盲注场景使用timebased组，报错注入场景使用orderby组

### 监控模式说明
- **Proxy监控**：启用后自动检测通过Proxy的所有HTTP流量
- **Repeater监控**：启用后自动检测Repeater发送的请求
- **Scanner/Intruder**：默认不自动监控，可通过右键菜单手动发送到插件
- **右键发送**：所有工具都支持通过右键菜单发送请求到插件进行检测
  - **使用当前组**：使用插件界面当前选中的payload组进行测试
  - **指定payload组**：可选择特定的payload组（如default、timebased、orderby等）进行针对性测试

### 配置目录位置

**默认配置目录（推荐）：**
```bash
# Windows
C:\Users\[用户名]\dousql\

# macOS
/Users/[用户名]/dousql/

# Linux  
/home/[用户名]/dousql/
```

**配置文件结构：**
```
~/dousql/
├── xia_SQL_diy_payload.ini           # 默认payload配置
├── xia_SQL_payload_timebased.ini     # 时间盲注payload组
├── xia_SQL_payload_orderby.ini       # 报错注入payload组
├── xia_SQL_diy_error.ini             # 自定义报错关键字
├── xia_SQL_response_time_threshold.ini # 响应时间阈值配置
├── xia_SQL_length_diff_threshold.ini  # 长度差异阈值配置
├── xia_SQL_blacklist_urls.ini        # 黑名单URL配置
├── xia_SQL_whitelist.ini             # 白名单参数配置
├── xia_SQL_blacklist.ini             # 黑名单参数配置
└── xia_SQL_param_filter_mode.ini     # 参数过滤模式配置
```

**特殊情况（jar包同级）：**
```
/path/to/extensions/
├── DouSql-3.0.5.jar          # 插件jar包
└── dousql/                   # 配置文件目录
    ├── xia_SQL_diy_payload.ini
    ├── xia_SQL_payload_timebased.ini
    └── ...
```

**配置目录检测日志示例：**
```
ProtectionDomain路径: /var/folders/.../tmp/burp.../20
使用用户主目录: /Users/username
hello DouSQL!
你好 欢迎使用 DouSQL!
version:3.0.5 (Montoya API)
jar包目录: /Users/username
配置文件目录: /Users/username/dousql
```

## 快速开始

### 方式一：直接下载
从 [Releases](https://github.com/darkfiv/DouSql/releases) 页面下载最新版本的jar文件

### 方式二：从源码编译
```bash
git clone https://github.com/darkfiv/DouSql.git
cd DouSql
mvn clean package
```

### 加载到Burp Suite
1. 打开Burp Suite
2. 进入 Extensions → Installed
3. 点击 Add 按钮
4. 选择编译生成的jar文件
5. 插件加载成功后，会在标签页看到"DouSQL"

## 使用方法

### 编译插件

**环境要求：**
- Java 11+
- Maven 3.x

**编译步骤：**
```bash
# 克隆项目
git clone https://github.com/darkfiv/DouSql.git
cd DouSql

# 编译打包
mvn clean package

# 编译完成后，jar文件位于：
# target/DouSql-3.0.5.jar
```

### 安装使用

1. 将编译生成的jar文件加载到Burp Suite
2. 在Extensions标签页中找到"DouSQL"插件
3. 配置相关检测参数和阈值
4. 通过右键菜单或监控模式发送请求进行检测
5. 查看扫描结果和参数测试详情

## 结果标记说明

### 检测结果标记
- **ERR!** - 响应中匹配到报错信息，表示疑似存在SQL注入漏洞
- **time > N** - 响应时间大于配置的时间阈值（N秒），表示疑似存在时间盲注
- **diff: ±N** - 响应长度与原始响应差异超过阈值，可能存在布尔盲注
- **✔ ==> ?** - 特殊payload响应长度变化，可能存在逻辑漏洞

### 状态标记
- **start** - 正在测试中
- **end!** - 测试完成
- **end! [err]** - 测试完成且发现报错信息
- **end! [time]** - 测试完成且发现时间异常

## 使用技巧

### 1. 根据应用场景配置payload组
- **时间盲注场景**：使用`timebased`组，包含各种延时payload
- **报错注入场景**：使用`orderby`组，包含报错类payload
- **自定义场景**：创建专门的payload组，针对特定应用优化

### 2. 合理配置参数过滤
- **无过滤模式**：测试所有检测到的参数，适合全面扫描
- **白名单模式**：只测试配置的关键参数（如id、username、password等）
- **黑名单模式**：排除配置的无关参数（如token、timestamp、csrf_token等）
- **独立存储**：白名单和黑名单参数分别保存，切换模式时不会丢失配置
- **提高效率**：避免测试大量无意义参数，专注于可能存在漏洞的参数

### 3. 设置黑名单URL
- 排除静态资源路径（如`/static/*`、`*.css`、`*.js`、`*.jpg`、`*.png`等）
- 排除管理后台路径（如`/admin/*`）
- 排除API文档路径（如`/swagger/*`、`/api-docs/*`）

### 4. 静态文件自动过滤
插件会自动跳过以下类型的静态文件：
- **图片文件**：jpg, jpeg, png, gif, bmp, tiff, tif, webp, svg, ico
- **样式和脚本**：css, js
- **字体文件**：woff, woff2, ttf, eot, otf
- **媒体文件**：mp3, mp4, avi, mov, wmv, flv, mkv
- **压缩文件**：zip, rar, 7z, tar, gz
- **文档文件**：pdf

### 5. 调整检测阈值
- **响应时间阈值**：根据目标服务器性能调整（建议2-5秒）
- **长度差异阈值**：根据应用响应特点调整（建议50-200字节）

### 6. 灵活使用右键菜单
- **快速测试**：选择"使用当前组"进行快速测试，使用插件界面当前选中的payload组
- **精确测试**：根据测试场景选择特定payload组：
  - **default组**：通用payload，适合初步探测
  - **timebased组**：专门的时间盲注payload，适合时间盲注场景
  - **orderby组**：报错注入payload，适合有报错回显的场景
  - **自定义组**：根据目标特点创建的专门payload组
- **测试策略**：可以先用default组进行快速扫描，发现可疑点后再用专门的payload组深入测试

## 重要提示

⚠️ **关于默认Payload**：
- 默认payload为作者日常SRC、渗透测试所用的通用payload
- 师傅们需要根据自己的实际场景去优化、添加POC
- 建议针对不同目标创建专门的payload组
- 可以根据目标技术栈（如Java、PHP、.NET等）定制payload


## 系统要求

**运行环境：**
- Burp Suite Professional 2024.6+
- Java 11+
- 支持Windows、macOS、Linux操作系统

**编译环境：**
- Java 11+
- Maven 3.x

## 开发环境

- Java版本：Java 11
- Burp Suite版本：2024.8.2
- 构建工具：Maven 3.x
- API框架：Montoya API (Burp Suite官方扩展API)

## 📋 更新记录

### 🚀 最新版本 V3.0.5 (2025-01-05)
- **完全修复中文参数编码问题**：支持UTF-8、GBK、GB2312等多种编码格式，解决中文参数乱码问题
- **增强JSON处理能力**：完美支持复杂嵌套JSON结构，优化响应显示逻辑
- **提升插件稳定性**：优化线程安全处理，移除冗余调试信息
- **支持右键请求发送到不同的payload测试组**
- **支持自定义参数追加并对指定参数做payload测试**

📖 **详细更新记录请查看 [CHANGELOG.md](CHANGELOG.md)**

## 新功能详解

### 多参数追加功能
插件支持同时追加多个参数，为每个请求自动添加指定的参数，常用于：
- 添加多个认证token或session参数
- 添加调试参数或标识参数
- 添加绕过WAF的多个参数

**界面设计**：
- **左右分割界面**：左侧配置参数列表，右侧控制测试开关
- **实时同步**：左侧参数变化时，右侧测试开关自动更新
- **独立控制**：每个参数都有独立的测试开关，默认关闭

**参数格式**：
```
token:abc123
debug:1
test:value
user_id:12345
```

**支持格式**：
- **URL参数**：自动添加到查询字符串
- **POST表单**：添加到表单数据中
- **JSON请求**：添加到JSON根级别

**重要特性**：
- 支持同时追加多个参数，每行一个
- 使用简单的 `key:value` 格式
- 每个参数可独立选择是否参与payload测试
- **不参与测试**：避免重复检测，提高效率
- **参与测试**：可能发现追加参数本身的漏洞
- 支持动态启用/禁用
- 配置持久化保存

**使用场景**：
- **认证绕过**：添加多个token参数但不测试，避免影响认证
- **漏洞发现**：添加可疑参数并参与测试，发现隐藏漏洞
- **WAF绕过**：添加多个干扰参数，灵活选择测试策略

### 自定义延时发包
插件支持三种延时模式，帮助避免被WAF检测或减轻目标服务器压力：

1. **无延时模式**：立即发送请求（默认）
2. **固定延时模式**：每个请求前等待固定时间
3. **随机延时模式**：在指定区间内随机延时

**配置说明**：
- 固定延时：可设置任意毫秒数（如1000ms = 1秒）
- 随机延时：默认1-5秒，可自定义最小值和最大值
- 实时生效：配置保存后立即应用到后续请求

## 交流群二维码老过期，有需要的师傅可关注安全鸭公众号，联系作者，私聊进群。

## 免责声明

本工具仅供安全测试和教育目的使用，使用者应遵守相关法律法规，不得用于非法用途。开发者不承担因误用本工具造成的任何责任。


