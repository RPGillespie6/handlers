// Copyright 2013 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package handlers

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/felixge/httpsnoop"
	"github.com/klauspost/compress/zstd"
)

const acceptEncoding string = "Accept-Encoding"

type compressResponseWriter struct {
	compressor io.Writer
	w          http.ResponseWriter
}

func (cw *compressResponseWriter) WriteHeader(c int) {
	cw.w.Header().Del("Content-Length")
	cw.w.WriteHeader(c)
}

func (cw *compressResponseWriter) Write(b []byte) (int, error) {
	h := cw.w.Header()
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", http.DetectContentType(b))
	}
	h.Del("Content-Length")

	return cw.compressor.Write(b)
}

func (cw *compressResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(cw.compressor, r)
}

type flusher interface {
	Flush() error
}

func (cw *compressResponseWriter) Flush() {
	// Flush compressed data if compressor supports it.
	if f, ok := cw.compressor.(flusher); ok {
		_ = f.Flush()
	}
	// Flush HTTP response.
	if f, ok := cw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// CompressHandler zstd compresses HTTP responses for clients that support it
// via the 'Accept-Encoding' header. If zstd is not supported, it will fall back
// to gzip or flate compression.
//
// Compressing TLS traffic may leak the page contents to an attacker if the
// page contains user input: http://security.stackexchange.com/a/102015/12208
func CompressHandler(h http.Handler) http.Handler {
	return CompressHandlerLevel(h, gzip.DefaultCompression)
}

// CompressHandlerLevel gzip compresses HTTP responses with specified compression level
// for clients that support it via the 'Accept-Encoding' header.
//
// The compression level should be gzip.DefaultCompression, gzip.NoCompression,
// or any integer value between gzip.BestSpeed and gzip.BestCompression inclusive.
// gzip.DefaultCompression is used in case of invalid compression level.
func CompressHandlerLevel(h http.Handler, level int) http.Handler {
	if level < gzip.DefaultCompression || level > gzip.BestCompression {
		level = gzip.DefaultCompression
	}

	const (
		gzipEncoding  = "gzip"
		flateEncoding = "deflate"
		zstdEncoding  = "zstd"
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// detect what encoding to use
		var encoding string
		encodings := strings.Split(r.Header.Get(acceptEncoding), ",")
		for i := range encodings {
			encodings[i] = strings.TrimSpace(encodings[i])
		}

		// zstd > gzip > flate
		if slices.Contains(encodings, zstdEncoding) {
			encoding = zstdEncoding
		} else if slices.Contains(encodings, gzipEncoding) {
			encoding = gzipEncoding
		} else if slices.Contains(encodings, flateEncoding) {
			encoding = flateEncoding
		}

		// always add Accept-Encoding to Vary to prevent intermediate caches corruption
		w.Header().Add("Vary", acceptEncoding)

		// if we weren't able to identify an encoding we're familiar with, pass on the
		// request to the handler and return
		if encoding == "" {
			h.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("Upgrade") != "" {
			h.ServeHTTP(w, r)
			return
		}

		// wrap the ResponseWriter with the writer for the chosen encoding
		var encWriter io.WriteCloser
		if encoding == zstdEncoding {
			// Map gzip compression levels to zstd compression levels
			zstdSpeed := zstd.SpeedDefault
			if level == gzip.BestSpeed {
				zstdSpeed = zstd.SpeedFastest
			} else if level == gzip.BestCompression {
				zstdSpeed = zstd.SpeedBestCompression
			}

			encWriter, _ = zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevel(zstdSpeed)))
		} else if encoding == gzipEncoding {
			encWriter, _ = gzip.NewWriterLevel(w, level)
		} else if encoding == flateEncoding {
			encWriter, _ = flate.NewWriter(w, level)
		}
		defer encWriter.Close()

		w.Header().Set("Content-Encoding", encoding)
		r.Header.Del(acceptEncoding)

		cw := &compressResponseWriter{
			w:          w,
			compressor: encWriter,
		}

		w = httpsnoop.Wrap(w, httpsnoop.Hooks{
			Write: func(httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return cw.Write
			},
			WriteHeader: func(httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return cw.WriteHeader
			},
			Flush: func(httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return cw.Flush
			},
			ReadFrom: func(rff httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return cw.ReadFrom
			},
		})

		h.ServeHTTP(w, r)
	})
}
