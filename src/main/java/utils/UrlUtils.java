package utils;

import burp.BurpExtender;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * URL处理工具类
 */
public class UrlUtils {
    private final BurpExtender burpExtender;
    private final Set<String> processedUrls = ConcurrentHashMap.newKeySet();
    
    public UrlUtils(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
    }
    
    /**
     * 检查URL是否已处理过
     */
    public boolean isProcessed(String method, String url) {
        String key = method + ":" + url;
        return processedUrls.contains(key);
    }
    
    /**
     * 添加已处理的URL
     */
    public void addProcessed(String method, String url) {
        String key = method + ":" + url;
        processedUrls.add(key);
    }
    
    /**
     * 移除URL参数值（保留参数名）
     */
    public String removeUrlParameterValue(String url) {
        try {
            URL urlObj = new URL(url);
            String query = urlObj.getQuery();
            
            if (query == null || query.isEmpty()) {
                return url;
            }
            
            StringBuilder newQuery = new StringBuilder();
            String[] params = query.split("&");
            
            for (int i = 0; i < params.length; i++) {
                String param = params[i];
                int equalIndex = param.indexOf('=');
                
                if (equalIndex > 0) {
                    newQuery.append(param.substring(0, equalIndex + 1));
                } else {
                    newQuery.append(param);
                }
                
                if (i < params.length - 1) {
                    newQuery.append("&");
                }
            }
            
            return urlObj.getProtocol() + "://" + urlObj.getHost() + 
                   (urlObj.getPort() != -1 ? ":" + urlObj.getPort() : "") +
                   urlObj.getPath() + "?" + newQuery.toString();
                   
        } catch (Exception e) {
            return url;
        }
    }
    
    /**
     * 清空已处理的URL
     */
    public void clearProcessed() {
        processedUrls.clear();
    }
}