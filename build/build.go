package build

import (
	"context"

	"github.com/outofforest/build/v2/pkg/types"
	"github.com/outofforest/tools/pkg/tools/zig"
)

func buildBootloader(ctx context.Context, deps types.DepsFunc) error {
	deps(zig.EnsureZig)

	return zig.Build(ctx, deps, zig.BuildConfig{
		PackagePath: "zig",
		OutputPath:  "bin",
	})
}
