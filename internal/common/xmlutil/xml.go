package xmlutil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-composer/internal/common/errors"
	"github.com/deploymenttheory/go-app-composer/internal/common/fsutil"
)

// CreateXMLFile creates a new XML file with the given root element.
func CreateXMLFile(path string, rootElement string) error {
	if fsutil.FileExists(path) {
		return fmt.Errorf("%w: %s", errors.ErrFileExistsError, path)
	}

	root := fmt.Sprintf("<%s></%s>", rootElement, rootElement)
	return fsutil.WriteFileString(path, root, 0644)
}

// ReadXMLFile reads an XML file and returns its contents as a byte slice.
func ReadXMLFile(path string) ([]byte, error) {
	if !fsutil.FileExists(path) {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileNotFound, path)
	}
	return fsutil.ReadFile(path)
}

// WriteXMLFile writes XML data to a file with indentation.
func WriteXMLFile(path string, v any) error {
	if !fsutil.DirExists(filepath.Dir(path)) {
		return fmt.Errorf("%w: %s", errors.ErrDirNotFound, path)
	}

	data, err := MarshalXML(v, true)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, data, 0644)
}

// UnmarshalXML unmarshals XML data into a provided struct.
func UnmarshalXML(data []byte, v any) error {
	if err := xml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
	}
	return nil
}

// MarshalXML marshals a struct into an XML byte slice.
func MarshalXML(v any, indent bool) ([]byte, error) {
	var data []byte
	var err error
	if indent {
		data, err = xml.MarshalIndent(v, "", "  ")
	} else {
		data, err = xml.Marshal(v)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errors.ErrFileWriteError, err.Error())
	}
	return data, nil
}

// ExtractElementValue extracts the text content of a specified XML element.
func ExtractElementValue(xmlStr, elementName string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
		}
		if startElem, ok := tok.(xml.StartElement); ok && startElem.Name.Local == elementName {
			var content string
			if err := decoder.DecodeElement(&content, &startElem); err != nil {
				return "", fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
			}
			return content, nil
		}
	}
	return "", fmt.Errorf("%w: element '%s' not found", errors.ErrInvalidArgument, elementName)
}

// DeleteElement removes an XML element from a file
func DeleteElement(path string, elementName string) error {
	data, err := ReadXMLFile(path)
	if err != nil {
		return err
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	inTarget := false

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == elementName {
				inTarget = true
				continue
			}
			encoder.EncodeToken(t)
		case xml.EndElement:
			if t.Name.Local == elementName {
				inTarget = false
				continue
			}
			encoder.EncodeToken(t)
		case xml.CharData:
			if inTarget {
				continue
			}
			encoder.EncodeToken(t)
		default:
			encoder.EncodeToken(tok)
		}
	}
	encoder.Flush()
	return fsutil.WriteFile(path, output.Bytes(), 0644)
}

// UpdateElement modifies the value of an XML element in a file
func UpdateElement(path string, elementName string, newValue string) error {
	data, err := ReadXMLFile(path)
	if err != nil {
		return err
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)

	var inTargetElement bool

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == elementName {
				inTargetElement = true
			}
			encoder.EncodeToken(t)

		case xml.CharData:
			if inTargetElement {
				t = xml.CharData([]byte(newValue))
				inTargetElement = false
			}
			encoder.EncodeToken(t)

		case xml.EndElement:
			if t.Name.Local == elementName {
				inTargetElement = false
			}
			encoder.EncodeToken(t)

		default:
			encoder.EncodeToken(tok)
		}
	}
	encoder.Flush()
	return fsutil.WriteFile(path, output.Bytes(), 0644)
}

// AddElement adds a new element to an XML file
func AddElement(path string, parentElement string, newElement string, value string) error {
	data, err := ReadXMLFile(path)
	if err != nil {
		return err
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %s", errors.ErrUnsupportedFile, err.Error())
		}

		encoder.EncodeToken(tok)
		if startElem, ok := tok.(xml.StartElement); ok && startElem.Name.Local == parentElement {
			newElem := xml.StartElement{Name: xml.Name{Local: newElement}}
			encoder.EncodeToken(newElem)
			encoder.EncodeToken(xml.CharData([]byte(value)))
			encoder.EncodeToken(newElem.End())
		}
	}
	encoder.Flush()
	return fsutil.WriteFile(path, output.Bytes(), 0644)
}
