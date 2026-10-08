package main

/*
#cgo LDFLAGS: -lxml2
#cgo pkg-config: libxml-2.0
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	xsdvalidate "github.com/terminalstatic/go-xsd-validate"
)

var (
	xsdValidateInitOnce sync.Once
	xsdValidateInitErr  error
	xsdValidatePathMu   sync.Mutex
)

func validateXMLSchemaBytes(schemaPath string, instanceData []byte) (err error) {
	xsdValidateInitOnce.Do(func() {
		xsdValidateInitErr = xsdvalidate.Init()
	})
	if xsdValidateInitErr != nil {
		return xsdValidateInitErr
	}

	xsdValidatePathMu.Lock()
	defer xsdValidatePathMu.Unlock()

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}
	schemaDir := filepath.Dir(schemaPath)
	schemaFile := filepath.Base(schemaPath)
	if err := os.Chdir(schemaDir); err != nil {
		return fmt.Errorf("changing to schema directory %s: %w", schemaDir, err)
	}
	defer func() {
		if chdirErr := os.Chdir(workingDir); chdirErr != nil && err == nil {
			err = fmt.Errorf("restoring working directory %s: %w", workingDir, chdirErr)
		}
	}()

	xsdHandler, err := xsdvalidate.NewXsdHandlerUrl(schemaFile, xsdvalidate.ParsErrVerbose)
	if err != nil {
		return fmt.Errorf("parsing schema %s: %w", schemaPath, err)
	}
	defer xsdHandler.Free()

	xmlHandler, err := xsdvalidate.NewXmlHandlerMem(instanceData, xsdvalidate.ParsErrVerbose)
	if err != nil {
		return fmt.Errorf("parsing instance XML: %w", err)
	}
	defer xmlHandler.Free()

	if err := xsdHandler.Validate(xmlHandler, xsdvalidate.ValidErrDefault); err != nil {
		return err
	}
	return nil
}
