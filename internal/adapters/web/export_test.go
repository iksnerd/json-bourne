package web

import "net"

func newLoopbackListener() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
