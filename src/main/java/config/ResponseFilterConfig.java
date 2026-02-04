package config;

import java.util.ArrayList;
import java.util.List;

/**
 * 响应过滤配置类
 */
public class ResponseFilterConfig {
    
    /**
     * 过滤条件类型
     */
    public enum FilterType {
        STATUS_CODE("状态码"),
        RESPONSE_HEADER("响应头"),
        RESPONSE_BODY("响应体内容"),
        RESPONSE_SIZE("响应大小");
        
        private final String displayName;
        
        FilterType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    /**
     * 比较操作符
     */
    public enum CompareOperator {
        EQUALS("等于"),
        NOT_EQUALS("不等于"),
        CONTAINS("包含"),
        NOT_CONTAINS("不包含"),
        GREATER_THAN("大于"),
        LESS_THAN("小于"),
        GREATER_EQUAL("大于等于"),
        LESS_EQUAL("小于等于");
        
        private final String displayName;
        
        CompareOperator(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    /**
     * 单个过滤条件
     */
    public static class FilterCondition {
        private FilterType type;
        private CompareOperator operator;
        private String value;
        private String headerName; // 当类型为响应头时使用
        private boolean enabled;
        
        public FilterCondition() {
            this.enabled = true;
        }
        
        public FilterCondition(FilterType type, CompareOperator operator, String value) {
            this.type = type;
            this.operator = operator;
            this.value = value;
            this.enabled = true;
        }
        
        // Getters and Setters
        public FilterType getType() { return type; }
        public void setType(FilterType type) { this.type = type; }
        
        public CompareOperator getOperator() { return operator; }
        public void setOperator(CompareOperator operator) { this.operator = operator; }
        
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
        
        public String getHeaderName() { return headerName; }
        public void setHeaderName(String headerName) { this.headerName = headerName; }
        
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        
        @Override
        public String toString() {
            String condition = type.getDisplayName() + " " + operator.getDisplayName() + " " + value;
            if (type == FilterType.RESPONSE_HEADER && headerName != null) {
                condition = type.getDisplayName() + "(" + headerName + ") " + operator.getDisplayName() + " " + value;
            }
            return condition + (enabled ? "" : " [已禁用]");
        }
    }
    
    private boolean enabled = false;
    private List<FilterCondition> conditions = new ArrayList<>();
    private boolean matchAll = true; // true: 所有条件都满足(AND), false: 任一条件满足(OR)
    
    public ResponseFilterConfig() {
        // 添加一些默认示例条件
        conditions.add(new FilterCondition(FilterType.STATUS_CODE, CompareOperator.EQUALS, "200"));
    }
    
    // Getters and Setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    public List<FilterCondition> getConditions() { return conditions; }
    public void setConditions(List<FilterCondition> conditions) { this.conditions = conditions; }
    
    public boolean isMatchAll() { return matchAll; }
    public void setMatchAll(boolean matchAll) { this.matchAll = matchAll; }
    
    public void addCondition(FilterCondition condition) {
        conditions.add(condition);
    }
    
    public void removeCondition(int index) {
        if (index >= 0 && index < conditions.size()) {
            conditions.remove(index);
        }
    }
    
    public void clearConditions() {
        conditions.clear();
    }
}