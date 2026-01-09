package domain

type Config struct {
	Version string
}

type Context struct {
	Config Config
	// Logger *log.Logger // Standard log is global, but we can wrap it if needed.
}
