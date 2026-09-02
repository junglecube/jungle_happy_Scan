package plugin

import "jungle_happy_Scan/internal/model"

// V2.0 models expensive or higher-impact checks as independently selectable
// capabilities. Presets only select plugin IDs; they never change what an
// already-selected plugin does.

type SQLInjectionExtended struct{}

func (SQLInjectionExtended) Meta() model.PluginMeta {
	return StandardMeta("sqli_extended", "SQL 注入扩展差分", "执行 PostgreSQL、GaussDB、MySQL、MyBatis 与存储过程的扩展错误/布尔配对规则；不提取业务数据。", "active", true)
}

func (p SQLInjectionExtended) Scan(ctx *Context) ([]model.Finding, error) {
	return scanSQLInjection(ctx, p.Meta(), sqlScanProfile{errorPairs: true, booleanPairs: true})
}

type SQLInjectionTiming struct{}

func (SQLInjectionTiming) Meta() model.PluginMeta {
	return StandardMeta("sqli_timing", "SQL 时间盲注", "单独执行数据库延时与零延时对照，并采用反向重复确认。", "active", true)
}

func (p SQLInjectionTiming) Scan(ctx *Context) ([]model.Finding, error) {
	return scanSQLInjection(ctx, p.Meta(), sqlScanProfile{timePairs: true})
}

type XXEExtended struct{}

func (XXEExtended) Meta() model.PluginMeta {
	return StandardMeta("xxe_extended", "XXE 扩展与回连", "执行 XInclude、编码实体及离线 HTTP 回连等扩展 XXE 检查。", "active", true)
}

func (p XXEExtended) Scan(ctx *Context) ([]model.Finding, error) { return scanXXE(ctx, p.Meta()) }

type FileReadEncoded struct{}

func (FileReadEncoded) Meta() model.PluginMeta {
	return StandardMeta("file_read_encoded", "任意文件读取编码绕过", "执行双重编码、路径混淆及扩展 Linux 文件目标检查。", "active", true)
}

func (p FileReadEncoded) Scan(ctx *Context) ([]model.Finding, error) {
	return scanFileRead(ctx, p.Meta())
}

type FileUploadExecution struct{}

func (FileUploadExecution) Meta() model.PluginMeta {
	return StandardMeta("file_upload_execution", "文件上传执行确认", "执行高风险扩展名上传，并在服务端返回同源路径时进行无害执行标记确认。", "state-changing", true)
}

func (p FileUploadExecution) Scan(ctx *Context) ([]model.Finding, error) {
	return scanFileUpload(ctx, p.Meta())
}

type CommandInjectionOAST struct{}

func (CommandInjectionOAST) Meta() model.PluginMeta {
	return StandardMeta("command_injection_oast", "OS 命令注入离线回连", "使用分隔符、反引号和美元括号curl回连确认无回显命令执行。", "active", true)
}

func (p CommandInjectionOAST) Scan(ctx *Context) ([]model.Finding, error) {
	return scanCommandInjection(ctx, p.Meta())
}

type CommandInjectionTiming struct{}

func (CommandInjectionTiming) Meta() model.PluginMeta {
	return StandardMeta("command_injection_timing", "OS 命令注入时间差分", "使用多Shell上下文的sleep与零延时控制进行成对时间差分。", "active", true)
}

func (p CommandInjectionTiming) Scan(ctx *Context) ([]model.Finding, error) {
	return scanCommandInjection(ctx, p.Meta())
}

type JavaExpressionExtended struct{}

func (JavaExpressionExtended) Meta() model.PluginMeta {
	return StandardMeta("java_expression_extended", "Java 表达式注入扩展", "执行 SpEL、OGNL、Thymeleaf 与 FreeMarker 的扩展无害算术表达式。", "active", true)
}

func (p JavaExpressionExtended) Scan(ctx *Context) ([]model.Finding, error) {
	return scanJavaExpression(ctx, p.Meta())
}

type MassAssignmentExtended struct{}

func (MassAssignmentExtended) Meta() model.PluginMeta {
	return StandardMeta("mass_assignment_extended", "Mass Assignment 扩展绑定", "扩展检查 multipart/query 混合绑定以及无明确内容类型的 Spring/CTP 绑定入口。", "state-changing", true)
}

func (p MassAssignmentExtended) Scan(ctx *Context) ([]model.Finding, error) {
	return scanMassAssignment(ctx, p.Meta(), true)
}

type GraphQLAliasAbuse struct{}

func (GraphQLAliasAbuse) Meta() model.PluginMeta {
	return StandardMeta("graphql_alias_abuse", "GraphQL 别名批处理限制", "单独验证大量 alias 或批量操作是否缺少数量/复杂度限制。", "active", true)
}

func (p GraphQLAliasAbuse) Scan(ctx *Context) ([]model.Finding, error) {
	return scanGraphQLSecurity(ctx, p.Meta())
}

type ErrorDisclosureExtended struct{}

func (ErrorDisclosureExtended) Meta() model.PluginMeta {
	return StandardMeta("error_disclosure_extended", "异常信息泄露扩展诱导", "使用类型、路径、表达式和边界值等扩展输入重复诱导 Java/Spring/ORM 内部错误。", "active", true)
}

func (p ErrorDisclosureExtended) Scan(ctx *Context) ([]model.Finding, error) {
	return scanErrorDisclosure(ctx, p.Meta())
}
