// Copyright 2018, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ocgrpc

import (
	"golang.org/x/net/context"

	"google.golang.org/grpc/stats"
)

// NewClientStatsHandler enables OpenCensus stats and trace
// for gRPC clients. Deprecated, construct a ClientHandler directly.
func NewClientStatsHandler() stats.Handler {
	return &ClientHandler{}
}

// ClientHandler implements a gRPC stats.Handler for recording OpenCensus stats and
// traces. Use with gRPC clients only.
type ClientHandler struct {
	// NoTrace may be set to disable recording OpenCensus Spans around
	// gRPC methods.
	NoTrace bool

	// NoStats may be set to disable recording OpenCensus Stats around each
	// gRPC method.
	NoStats bool
}

func (c *ClientHandler) HandleConn(ctx context.Context, cs stats.ConnStats) {
	// no-op
}

func (c *ClientHandler) TagConn(ctx context.Context, cti *stats.ConnTagInfo) context.Context {
	// no-op
	return ctx
}

func (c *ClientHandler) HandleRPC(ctx context.Context, rs stats.RPCStats) {
	if !c.NoTrace {
		c.traceHandleRPC(ctx, rs)
	}
	if !c.NoStats {
		c.statsHandleRPC(ctx, rs)
	}
}

func (c *ClientHandler) TagRPC(ctx context.Context, rti *stats.RPCTagInfo) context.Context {
	if !c.NoTrace {
		ctx = c.traceTagRPC(ctx, rti)
	}
	if !c.NoStats {
		ctx = c.statsTagRPC(ctx, rti)
	}
	return ctx
}
