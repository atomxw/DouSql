# JSON数组参数注入修复说明

## 问题描述

当测试包含数组参数的JSON请求时，例如：
```json
{
  "data": {
    "data": {
      "encData": "4A8E4673BB18D86FE780DACC31C49FE3"
    },
    "signData": "8ftTZ/EOd5IrNmmk/fghdSnUEMCWd2b2OJnsUjb8gtVrRk+AkztLmQU3JFNOyZVwDHktXqo4hjiDja+5hKGchA==",
    "role_permissions": [1, 2, 3, 4, 5, 6, 7, 16, 25]
  }
}
```

### 旧行为（错误）
测试 `role_permissions` 参数时，整个数组被替换为字符串：
```json
{
  "role_permissions": "1'"
}
```

### 新行为（正确）
测试 `role_permissions` 参数时，修改数组的第一个元素：
```json
{
  "role_permissions": ["1'", 2, 3, 4, 5, 6, 7, 16, 25]
}
```

## 修复方案

修改了 `HttpUtils.java` 中的 `injectPayloadIntoJsonArray` 方法：

1. **保持数组格式**：不再将数组替换为字符串
2. **修改第一个元素**：
   - 将第一个元素转换为字符串（如果是数字）
   - 追加 payload 到第一个元素
   - 保持其他元素不变

3. **新增辅助方法** `splitJsonArrayElements`：
   - 正确解析JSON数组元素
   - 处理嵌套对象和数组
   - 处理字符串中的逗号

## 测试用例

### 用例1：数字数组
**输入：**
```json
"role_permissions": [1, 2, 3, 4, 5]
```
**Payload：** `'`
**输出：**
```json
"role_permissions": ["1'", 2, 3, 4, 5]
```

### 用例2：字符串数组
**输入：**
```json
"permissions": ["read", "write", "delete"]
```
**Payload：** `' OR '1'='1`
**输出：**
```json
"permissions": ["read' OR '1'='1", "write", "delete"]
```

### 用例3：空数组
**输入：**
```json
"items": []
```
**Payload：** `1'`
**输出：**
```json
"items": ["1'"]
```

### 用例4：混合类型数组
**输入：**
```json
"mixed": [1, "test", true, null]
```
**Payload：** `'`
**输出：**
```json
"mixed": ["1'", "test", true, null]
```

## 技术细节

### 数组元素分割算法
- 跟踪字符串状态（是否在引号内）
- 跟踪嵌套深度（处理嵌套数组和对象）
- 处理转义字符
- 只在顶层逗号处分割

### JSON值转义
- 正确转义特殊字符（引号、反斜杠等）
- 保持JSON格式有效性

## 注意事项

1. 该修复只影响JSON数组参数的处理
2. 普通JSON参数（字符串、数字、对象）的处理逻辑不变
3. 如果数组解析失败，会降级到原有的字符串替换行为
4. 修改后的请求仍然是有效的JSON格式
