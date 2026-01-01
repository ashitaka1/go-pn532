// Copyright 2026 The Zaparoo Project Contributors.
// SPDX-License-Identifier: Apache-2.0
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

package ndef

// Common MIME types used in NFC.
const (
	MIMETypeWiFi  = "application/vnd.wfa.wsc"
	MIMETypeVCard = "text/vcard"
	MIMETypeJSON  = "application/json"
	MIMETypeText  = "text/plain"
)

// NewMediaRecord creates a new NDEF Media-type record.
// The mediaType parameter should be a MIME type (e.g., "text/plain", "application/json").
func NewMediaRecord(mediaType string, payload []byte) *Record {
	return &Record{
		TNF:     TNFMedia,
		Type:    mediaType,
		Payload: payload,
	}
}

// NewExternalRecord creates a new NDEF External Type record.
// External types use the format "domain:type" (e.g., "example.com:mytype").
func NewExternalRecord(externalType string, payload []byte) *Record {
	return &Record{
		TNF:     TNFExternal,
		Type:    externalType,
		Payload: payload,
	}
}

// NewAbsoluteURIRecord creates a new NDEF Absolute URI record.
// This is different from a URI well-known type record - the URI itself is the type.
func NewAbsoluteURIRecord(uri string, payload []byte) *Record {
	return &Record{
		TNF:     TNFAbsoluteURI,
		Type:    uri,
		Payload: payload,
	}
}

// NewEmptyRecord creates an empty NDEF record.
func NewEmptyRecord() *Record {
	return &Record{
		TNF: TNFEmpty,
	}
}
