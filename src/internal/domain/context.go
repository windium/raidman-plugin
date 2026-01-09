package domain

type Config struct {
	Version string
	Host    string
	Port    string
}

type Context struct {
	Config Config
	// Logger *log.Logger // Standard log is global, but we can wrap it if needed.
}
