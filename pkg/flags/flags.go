package flags

import (
	"os"
	"strings"

	"github.com/spf13/pflag"
)

func SetFromEnv(fs *pflag.FlagSet) {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	fs.VisitAll(func(f *pflag.Flag) {
		if !f.Changed {
			if v, ok := os.LookupEnv(strings.ToUpper(replacer.Replace(f.Name))); ok {
				f.Value.Set(v)
			}
		}
	})
}
