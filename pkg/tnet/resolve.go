package tnet

import (
	"context"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/retry"
	"github.com/outofforest/parallel"
)

// ResolveHosts resolves hosts to their IPs.
func ResolveHosts(ctx context.Context, hosts ...string) (map[string]net.IP, error) {
	type result struct {
		Host string
		IP   net.IP
	}

	retryCtx, retryCancel := context.WithTimeout(ctx, time.Minute)
	defer retryCancel()

	results := make(map[string]net.IP, len(hosts))
	err := parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		resultsCh := make(chan result)

		spawn("integrator", parallel.Exit, func(ctx context.Context) error {
			for res := range resultsCh {
				results[res.Host] = res.IP
			}
			return nil
		})

		spawn("workers", parallel.Continue, func(ctx context.Context) error {
			defer close(resultsCh)

			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				for _, h := range hosts {
					spawn(h, parallel.Continue, func(ctx context.Context) error {
						return retry.Do(retryCtx, retry.DefaultExpBackoffConfig, func() error {
							ips, err := net.LookupIP(h)
							if err != nil {
								return retry.Retriable(errors.WithStack(err))
							}
							resultsCh <- result{Host: h, IP: ips[0].To4()}
							return nil
						})
					})
				}
				return nil
			})
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}
