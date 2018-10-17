package service

import (
	"github.com/prometheus/common/log"
	"github.com/spf13/viper"
)

// InitConfig initializes a new configuration file
func InitConfig(path string) *viper.Viper {
	v := viper.New()
	v.AddConfigPath(path)
	v.SetConfigName("base")
	v.AutomaticEnv()
	err := v.MergeInConfig()
	if err != nil {
		log.Fatal(err)
	}

	env := v.GetString("ENV")
	if env != "" {
		v.SetConfigName(env)
		err = v.MergeInConfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	return v
}
