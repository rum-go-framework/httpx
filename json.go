package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// DefaultMaxBodyBytes is the request body cap used by DecodeJSONBody.
const DefaultMaxBodyBytes = 1 << 20 // 1 MiB

// MalformedRequest is returned by the decoders for client errors; Status is
// the HTTP status the handler should answer with.
type MalformedRequest struct {
	Status int
	Msg    string
}

func (mr *MalformedRequest) Error() string { return mr.Msg }

func malformed(status int, format string, args ...any) *MalformedRequest {
	return &MalformedRequest{Status: status, Msg: fmt.Sprintf(format, args...)}
}

// DecodeJSONBody strictly decodes a single JSON value from r into dst with a
// DefaultMaxBodyBytes cap. See DecodeJSONBodyLimit.
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	return DecodeJSONBodyLimit(w, r, dst, DefaultMaxBodyBytes)
}

// DecodeJSONBodyLimit strictly decodes a single JSON value from r into dst:
// unknown fields and trailing data are rejected and the body is capped at
// maxBytes. Client errors are returned as *MalformedRequest; anything else is
// an unexpected I/O error.
func DecodeJSONBodyLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		// A garbage header yields an empty media type, which is rejected too.
		mt, _, _ := mime.ParseMediaType(ct)
		if mt != "application/json" {
			return malformed(http.StatusUnsupportedMediaType, "Content-Type header is not application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		// Padding after the value can push the body over the cap.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return decodeError(err)
		}
		return malformed(http.StatusBadRequest, "Request body must only contain a single JSON value")
	}
	return nil
}

func decodeError(err error) error {
	var (
		syntaxErr  *json.SyntaxError
		typeErr    *json.UnmarshalTypeError
		maxBytesEr *http.MaxBytesError
	)
	switch {
	case errors.As(err, &syntaxErr):
		return malformed(http.StatusBadRequest, "Request body contains badly-formed JSON (at position %d)", syntaxErr.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return malformed(http.StatusBadRequest, "Request body contains badly-formed JSON")
	case errors.As(err, &typeErr):
		return malformed(http.StatusBadRequest, "Request body contains an invalid value for the %q field (at position %d)", typeErr.Field, typeErr.Offset)
	case errors.Is(err, io.EOF):
		return malformed(http.StatusBadRequest, "Request body must not be empty")
	case errors.As(err, &maxBytesEr):
		return malformed(http.StatusRequestEntityTooLarge, "Request body must not be larger than %d bytes", maxBytesEr.Limit)
	}
	// encoding/json exposes no typed error for unknown fields.
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return malformed(http.StatusBadRequest, "Request body contains unknown field %s", field)
	}
	return err
}

// Response is the uniform JSON envelope written by JSONResponse.
type Response struct {
	Status       bool   `json:"status"`
	Code         int    `json:"code"`
	ResponseCode int    `json:"response_code,omitempty"`
	Message      string `json:"message,omitempty"`
	Data         any    `json:"data,omitempty"`
}

// JSONResponse writes the Response envelope. The optional statusCodes are the
// HTTP status (default 200) and an application-level response code.
// Status is true for 2xx codes.
func JSONResponse(w http.ResponseWriter, message string, data any, statusCodes ...int) {
	resp := Response{Code: http.StatusOK, Message: message, Data: data}
	if len(statusCodes) > 0 {
		resp.Code = statusCodes[0]
	}
	if len(statusCodes) > 1 {
		resp.ResponseCode = statusCodes[1]
	}
	resp.Status = resp.Code >= 200 && resp.Code < 300

	// Encode first: once the header is written a marshal failure could no
	// longer be turned into a 500.
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.Code)
	_, _ = w.Write(append(body, '\n'))
}
