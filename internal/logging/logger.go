package logging

// 日志标志位定义（与 C 端 unified_config.h 保持一致）
const (
	LogDebugPkg = 1 << iota // 0x01 - 调试数据包处理
	LogUdpEcho              // 0x02 - UDP Echo 相关日志
	LogSnat                 // 0x04 - SNAT 处理日志
	LogDnat                 // 0x08 - DNAT 处理日志
	LogAll = 0xFF           // 0xFF - 所有日志
)

// Logger 带日志开关控制的日志记录器
type Logger struct {
	logFlags uint32
}

// NewLogger 创建新的日志记录器
func NewLogger(logFlags uint32) *Logger {
	return &Logger{
		logFlags: logFlags,
	}
}

// SetLogFlags 更新日志标志位
func (l *Logger) SetLogFlags(flags uint32) {
	l.logFlags = flags
}

// GetLogFlags 获取当前日志标志位
func (l *Logger) GetLogFlags() uint32 {
	return l.logFlags
}

// IsEnabled 检查指定日志类型是否启用
func (l *Logger) IsEnabled(flag uint32) bool {
	return l.logFlags&flag != 0
}

// DebugPkgEnabled 检查调试数据包日志是否启用
func (l *Logger) DebugPkgEnabled() bool {
	return l.logFlags&LogDebugPkg != 0
}

// UdpEchoEnabled 检查 UDP Echo 日志是否启用
func (l *Logger) UdpEchoEnabled() bool {
	return l.logFlags&LogUdpEcho != 0
}

// SnatEnabled 检查 SNAT 日志是否启用
func (l *Logger) SnatEnabled() bool {
	return l.logFlags&LogSnat != 0
}

// DnatEnabled 检查 DNAT 日志是否启用
func (l *Logger) DnatEnabled() bool {
	return l.logFlags&LogDnat != 0
}
