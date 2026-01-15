# Payload 组测试验证

## 测试步骤

1. **加载插件**
   - 在 Burp Suite 中加载 `target/DouSql-3.0.6.jar`
   - 查看 Extender -> Output 确认加载成功

2. **验证 Payload 组**
   - 打开插件界面
   - 查看 Payload 组下拉框
   - 应该看到以下 7 个组：
     - default
     - order测试组
     - blind-injection-fuzz
     - login-password-injection-fuzz
     - mssql-payloads-fuzz
     - oracle-payloads-fuzz
     - union-select-bypass

3. **验证 Payload 内容**
   - 切换到每个组
   - 查看 Payload 列表区域
   - 确认 payload 数量：
     - default: 21 个
     - order测试组: 3 个
     - blind-injection-fuzz: 42 个
     - login-password-injection-fuzz: 73 个
     - mssql-payloads-fuzz: 14 个
     - oracle-payloads-fuzz: 8 个
     - union-select-bypass: 30 个

4. **验证右键菜单**
   - 在 Proxy/Repeater 中右键点击请求
   - 选择 "Send to DouSql"
   - 应该看到所有 7 个 payload 组的子菜单

5. **验证空格编码修复**
   - 勾选 "空格url编码" 选项
   - 发送包含空格的 payload 测试
   - 查看 Output 日志，确认：
     - `[processCustomPayload] 编码前: [ AND ...]`
     - `[processCustomPayload] 编码后: [%20AND ...]`
     - `即将传递给buildParameter的testValue: [1%20AND ...]`

## 预期结果

### Output 日志示例
```
已初始化payload组，共7个组: [default, order测试组, blind-injection-fuzz, login-password-injection-fuzz, mssql-payloads-fuzz, oracle-payloads-fuzz, union-select-bypass]
```

### 空格编码日志示例
```
=== Payload编码处理调试 ===
  -> 原始payload: [ AND (SELECT 8778 FROM (SELECT(SLEEP(5)))nXpZ)']
  -> urlEncodeSpaces设置: true
  -> customPayloadEnabled设置: false
    [processCustomPayload] 开始处理
    [processCustomPayload] 输入payload: [ AND (SELECT 8778 FROM (SELECT(SLEEP(5)))nXpZ)']
    [processCustomPayload] urlEncodeSpaces: true
    [processCustomPayload] 执行空格编码...
    [processCustomPayload] 编码前: [ AND (SELECT 8778 FROM (SELECT(SLEEP(5)))nXpZ)']
    [processCustomPayload] 编码后: [%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)']
  -> 处理后的payload: [%20AND%20(SELECT%208778%20FROM%20(SELECT(SLEEP(5)))nXpZ)']
```

## 常见问题

### Q1: 看不到新的 payload 组？
**A**: 确保重新加载了插件，旧版本不会自动更新

### Q2: Payload 数量不对？
**A**: 检查是否有自定义配置文件覆盖了内置 payload

### Q3: 空格编码不生效？
**A**: 
1. 确认勾选了 "空格url编码" 选项
2. 查看 Output 日志确认 `urlEncodeSpaces: true`
3. 检查 payload 是否真的包含空格

### Q4: 如何恢复默认 payload？
**A**: 
1. 删除 `~/dousql/` 目录下的配置文件
2. 重新加载插件
3. 插件会自动使用内置的默认 payload

## 性能测试

### 测试场景 1: 快速扫描
- 使用 default 组（21 个 payload）
- 测试 5 个参数
- 预计发送 105 个请求

### 测试场景 2: 深度测试
- 使用 blind-injection-fuzz 组（42 个 payload）
- 测试 5 个参数
- 预计发送 210 个请求

### 测试场景 3: 全面测试
- 依次使用所有 7 个组
- 测试 5 个参数
- 预计发送 955 个请求（191 × 5）

## 建议

1. **首次使用**：先用 default 组测试，熟悉插件功能
2. **生产环境**：谨慎使用大型 payload 组，注意请求频率
3. **自定义优化**：根据实际场景创建专用 payload 组
4. **保存配置**：重要的 payload 组记得保存到配置文件
