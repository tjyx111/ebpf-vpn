package logging

// 日志标志位定义（与 C 端 unified_config.h 保持一致）
const (
	LogDebugPkg = 1 << iota // 0x01 - 调试数据包处理
	_                       // 0x02 - 已废弃（UDP Echo）
	LogSnat                 // 0x04 - SNAT 处理日志
	LogDnat                 // 0x08 - DNAT 处理日志
	_                       // 0x10 - 已废弃（配置日志）
	_                       // 0x20 - 已废弃（VPN 封装）
	_                       // 0x40 - 已废弃（VPN 解封装）
	_                       // 0x80 - 已废弃（ICMP）
	_                       // 0x100 - 已废弃（抓包）
	_                       // 0x200 - 已废弃（错误）
	_                       // 0x400 - 已废弃（警告）
	_                       // 0x800 - 已废弃（信息）
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

// SnatEnabled 检查 SNAT 日志是否启用
func (l *Logger) SnatEnabled() bool {
	return l.logFlags&LogSnat != 0
}

// DnatEnabled 检查 DNAT 日志是否启用
func (l *Logger) DnatEnabled() bool {
	return l.logFlags&LogDnat != 0
}
