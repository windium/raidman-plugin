package domain

type Config struct {
	Version string
	Host    string
	Port    string
}

type Context struct {
	Config Config
}
