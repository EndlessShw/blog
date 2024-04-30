package com.endlessshw.spelrce.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

/**
 * @author hasee
 * @version 1.0
 * @description: SpEL RCE 靶场
 * @date 2023/4/4 15:15
 */
@RestController
@RequestMapping("/rce")
public class SpEL_RceController {
    @GetMapping("/spel")
    public String SpELRce(String cmd) {
        // 创建一个 Spel 表达式解析器
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
        // 根据传入的 cmd 来创建表达式
        Expression expression = spelExpressionParser.parseExpression(cmd);
        return Objects.requireNonNull(expression.getValue()).toString();
    }

    @GetMapping("/spelcontext")
    public String SpELRceWithContext(String cmd) {
        // 创建一个 Spel 表达式解析器
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
        // 构造上下文，准备表达式需要的上下文数据（用于自定义变量、函数、类型转换器等）
        // Create a new TemplateParserContext with the default "#{" prefix and "}" suffix.
        TemplateParserContext templateParserContext = new TemplateParserContext();
        // 根据传入的 cmd 来创建表达式
        Expression expression = spelExpressionParser.parseExpression(cmd, templateParserContext);
        return Objects.requireNonNull(expression.getValue()).toString();
    }
}
