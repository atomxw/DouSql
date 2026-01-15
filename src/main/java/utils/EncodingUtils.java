package utils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.util.regex.Pattern;

/**
 * 编码处理工具类
 * 专门处理中文参数编码问题，实现3.0.5版本的编码修复功能
 * 兼容Legacy Burp API
 */
public class EncodingUtils {
    private final LegacyLoggingWrapper logging;
    
    // 中文字符检测正则
    private static final Pattern CHINESE_PATTERN = Pattern.compile("[\u4e00-\u9fff]");
    
    public EncodingUtils(LegacyLoggingWrapper logging) {
        this.logging = logging;
    }
    
    /**
     * 修复参数值的中文编码问题
     * 完全按照test.txt和daimabak.txt中成功的方法：ISO_8859_1→UTF_8直接转换
     */
    public String fixChineseEncoding(String originalValue) {
        if (originalValue == null || originalValue.isEmpty()) {
            return originalValue;
        }
        
        try {
            logging.logToOutput("=== 中文编码修复开始 ===");
            logging.logToOutput("原始参数值: " + originalValue);
            
            // 完全按照test.txt的方法进行中文编码修复
            byte[] bytes = originalValue.getBytes(StandardCharsets.ISO_8859_1);
            String workingValue = new String(bytes, StandardCharsets.UTF_8);
            
            logging.logToOutput("ISO-8859-1字节: " + java.util.Arrays.toString(bytes));
            logging.logToOutput("修复后值: " + workingValue);
            
            // 检查是否包含中文字符
            boolean originalHasChinese = containsChineseCharacters(originalValue);
            boolean workingHasChinese = containsChineseCharacters(workingValue);
            
            logging.logToOutput("原始值包含中文: " + originalHasChinese);
            logging.logToOutput("修复后包含中文: " + workingHasChinese);
            
            // 如果原始值已经包含中文，可能不需要修复
            if (originalHasChinese && !workingHasChinese) {
                logging.logToOutput("警告：修复后中文字符丢失，使用原始值");
                logging.logToOutput("=== 中文编码修复完成（使用原始值）===");
                return originalValue;
            } else if (originalHasChinese && workingHasChinese) {
                logging.logToOutput("注意：原始值和修复后值都包含中文，使用原始值");
                logging.logToOutput("=== 中文编码修复完成（使用原始值）===");
                return originalValue;
            } else if (!originalHasChinese && workingHasChinese) {
                logging.logToOutput("成功修复中文编码");
                logging.logToOutput("=== 中文编码修复完成（使用修复值）===");
                return workingValue;
            } else {
                logging.logToOutput("无需修复");
                logging.logToOutput("=== 中文编码修复完成（无需修复）===");
                return originalValue;
            }
            
        } catch (Exception e) {
            logging.logToError("中文编码修复失败: " + e.getMessage());
            return originalValue;
        }
    }
    
    /**
     * 核心编码修复方法 - 实现ISO_8859_1→UTF_8转换
     * 完全采用test.txt的中文编码修复方法
     */
    private String fixEncodingIssue(String value) {
        try {
            // 方法1: 直接ISO_8859_1→UTF_8转换（test.txt成功案例）
            byte[] iso88591Bytes = value.getBytes(StandardCharsets.ISO_8859_1);
            String utf8Value = new String(iso88591Bytes, StandardCharsets.UTF_8);
            
            logging.logToOutput("ISO_8859_1→UTF_8转换结果: " + utf8Value);
            
            // 验证转换结果是否包含正确的中文字符
            if (containsChineseCharacters(utf8Value) && !containsGarbledText(utf8Value)) {
                logging.logToOutput("ISO_8859_1→UTF_8转换成功");
                return utf8Value;
            }
            
            // 方法2: 尝试其他编码组合
            String[] sourceEncodings = {"ISO-8859-1", "UTF-8", "GBK", "GB2312"};
            String[] targetEncodings = {"UTF-8", "GBK", "GB2312"};
            
            for (String sourceEncoding : sourceEncodings) {
                for (String targetEncoding : targetEncodings) {
                    try {
                        byte[] sourceBytes = value.getBytes(sourceEncoding);
                        String converted = new String(sourceBytes, targetEncoding);
                        
                        if (containsChineseCharacters(converted) && !containsGarbledText(converted)) {
                            logging.logToOutput("成功转换: " + sourceEncoding + "→" + targetEncoding);
                            return converted;
                        }
                    } catch (Exception ignored) {
                        // 继续尝试其他编码
                    }
                }
            }
            
            // 如果所有转换都失败，返回原值
            logging.logToOutput("所有编码转换尝试失败，返回原值");
            return value;
            
        } catch (Exception e) {
            logging.logToError("编码转换异常: " + e.getMessage());
            return value;
        }
    }
    
    /**
     * 检测字符串是否包含中文字符
     */
    public boolean containsChineseCharacters(String text) {
        if (text == null) return false;
        return CHINESE_PATTERN.matcher(text).find();
    }
    
    /**
     * 检测是否为乱码文本
     */
    private boolean containsGarbledText(String text) {
        if (text == null) return true;
        
        // 检测常见乱码特征
        String[] garbledPatterns = {
            "ï¿½", "â€", "Ã", "Â", "ã€", "ï¼", "ã€‚"
        };
        
        for (String pattern : garbledPatterns) {
            if (text.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 为参数值和payload组合创建工作值
     * 实现CHANGELOG.md中提到的workingValue + payload逻辑
     */
    public String createWorkingValue(String originalValue, String payload) {
        logging.logToOutput("=== 创建工作值 ===");
        logging.logToOutput("原始参数值: " + originalValue);
        logging.logToOutput("Payload: " + payload);
        
        // 首先修复原始值的编码问题
        String fixedOriginalValue = fixChineseEncoding(originalValue);
        
        // 创建工作值：修复后的原值 + payload
        String workingValue = fixedOriginalValue + payload;
        
        logging.logToOutput("工作值: " + workingValue);
        logging.logToOutput("=== 工作值创建完成 ===");
        
        return workingValue;
    }
    
    /**
     * 修复JSON参数中的中文字符
     * 增强JSON参数中文字符处理
     */
    public String fixJsonChineseEncoding(String jsonValue) {
        if (jsonValue == null || jsonValue.isEmpty()) {
            return jsonValue;
        }
        
        logging.logToOutput("=== JSON中文编码修复 ===");
        logging.logToOutput("原始JSON值: " + jsonValue);
        
        try {
            // 对JSON值进行编码修复
            String fixedValue = fixChineseEncoding(jsonValue);
            
            // JSON特殊处理：确保JSON格式正确
            if (fixedValue.startsWith("\"") && fixedValue.endsWith("\"")) {
                // 已经是JSON字符串格式
                logging.logToOutput("JSON字符串格式正确");
            } else if (containsChineseCharacters(fixedValue)) {
                // 包含中文但不是JSON字符串格式，需要转义
                fixedValue = escapeJsonString(fixedValue);
                logging.logToOutput("JSON字符串已转义");
            }
            
            logging.logToOutput("修复后JSON值: " + fixedValue);
            logging.logToOutput("=== JSON中文编码修复完成 ===");
            
            return fixedValue;
            
        } catch (Exception e) {
            logging.logToError("JSON中文编码修复失败: " + e.getMessage());
            return jsonValue;
        }
    }
    
    /**
     * 转义JSON字符串中的特殊字符
     */
    private String escapeJsonString(String value) {
        if (value == null) return null;
        
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\b", "\\b")
                   .replace("\f", "\\f")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
    
    /**
     * 获取参数的调试信息
     * 提供详细的编码调试信息
     */
    public void logParameterEncodingDebug(String paramName, String originalValue) {
        logging.logToOutput("=== 参数编码调试信息 ===");
        logging.logToOutput("参数名: " + paramName);
        logging.logToOutput("原始值: " + originalValue);
        
        if (originalValue != null) {
            logging.logToOutput("原始值长度: " + originalValue.length());
            logging.logToOutput("原始值字节数组: " + java.util.Arrays.toString(originalValue.getBytes()));
            logging.logToOutput("包含中文字符: " + containsChineseCharacters(originalValue));
            
            // 尝试不同编码的解码结果
            String[] encodings = {"UTF-8", "GBK", "GB2312", "ISO-8859-1"};
            for (String encoding : encodings) {
                try {
                    byte[] bytes = originalValue.getBytes(encoding);
                    String decoded = new String(bytes, StandardCharsets.UTF_8);
                    logging.logToOutput(encoding + " 编码结果: " + decoded);
                } catch (Exception e) {
                    logging.logToOutput(encoding + " 编码失败: " + e.getMessage());
                }
            }
        }
        
        logging.logToOutput("=== 参数编码调试完成 ===");
    }
}