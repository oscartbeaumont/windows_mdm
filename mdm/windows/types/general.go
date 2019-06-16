package windowstype

import (
	"encoding/xml"
	"errors"
	"net/url"
)

// TODO: Go Doc for this package

var ( // TODO: Redo error messages. Include that the errors are in the header for debugging
	ErrInvalidAction         = errors.New("the action is not valid")
	ErrEmptyMessageID      = errors.New("invalid message id")
	ErrEmptyReplyToAddress = errors.New("invalid reply to address")
	ErrEmptyToDomain       = errors.New("invalid to domain")
	ErrInvalidToPath         = errors.New("invalid to path")
)

type URL url.URL

func (u *URL) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var urlStr string
	d.DecodeElement(&urlStr, &start)
	urlParsed, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	*u = URL(*urlParsed) // TODO: This is super janky and should probally be cleaned up in the future
	return nil
}
