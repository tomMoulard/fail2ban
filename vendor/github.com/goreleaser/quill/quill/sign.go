package quill

import (
	"fmt"
	"os"
	"path"

	blacktopMacho "github.com/blacktop/go-macho"

	macholibre "github.com/anchore/go-macholibre"
	"github.com/goreleaser/quill/quill/macho"
	"github.com/goreleaser/quill/quill/pki"
	"github.com/goreleaser/quill/quill/pki/load"
	"github.com/goreleaser/quill/quill/sign"
)

type SigningConfig struct {
	SigningMaterial pki.SigningMaterial
	Identity        string
	Path            string
	Entitlements    string
}

func NewSigningConfigFromPEMs(binaryPath, certificate, privateKey, password string, failWithoutFullChain bool) (*SigningConfig, error) {
	var signingMaterial pki.SigningMaterial
	if certificate != "" {
		sm, err := pki.NewSigningMaterialFromPEMs(certificate, privateKey, password, failWithoutFullChain)
		if err != nil {
			return nil, err
		}

		signingMaterial = *sm
	}

	return &SigningConfig{
		Path:            binaryPath,
		Identity:        path.Base(binaryPath),
		SigningMaterial: signingMaterial,
	}, nil
}

func NewSigningConfigFromP12(binaryPath string, p12Content load.P12Contents, failWithoutFullChain bool) (*SigningConfig, error) {
	signingMaterial, err := pki.NewSigningMaterialFromP12(p12Content, failWithoutFullChain)
	if err != nil {
		return nil, err
	}

	return &SigningConfig{
		Path:            binaryPath,
		Identity:        path.Base(binaryPath),
		SigningMaterial: *signingMaterial,
	}, nil
}

func (c *SigningConfig) WithIdentity(id string) *SigningConfig {
	if id != "" {
		c.Identity = id
	}
	return c
}

func (c *SigningConfig) WithTimestampServer(url string) *SigningConfig {
	c.SigningMaterial.TimestampServer = url
	return c
}

func (c *SigningConfig) WithEntitlements(path string) *SigningConfig {
	c.Entitlements = path
	return c
}

func Sign(cfg SigningConfig) error {
	f, err := os.Open(cfg.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		return signMultiarchBinary(cfg)
	}

	return signSingleBinary(cfg)
}

//nolint:funlen
func signMultiarchBinary(cfg SigningConfig) error {
	f, err := os.Open(cfg.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	dir, err := os.MkdirTemp("", "quill-extract-"+path.Base(cfg.Path))
	if err != nil {
		return fmt.Errorf("unable to create temp directory to extract multi-arch binary: %w", err)
	}
	defer os.RemoveAll(dir)

	extractedFiles, err := macholibre.Extract(f, dir)
	if err != nil {
		return fmt.Errorf("unable to extract multi-arch binary: %w", err)
	}

	var cfgs []SigningConfig
	for _, ef := range extractedFiles {
		c := cfg
		c.Path = ef.Path
		cfgs = append(cfgs, c)
	}

	for _, c := range cfgs {
		if err := signSingleBinary(c); err != nil {
			return err
		}
	}

	var paths []string
	for _, c := range cfgs {
		paths = append(paths, c.Path)
	}

	if err := macholibre.Package(cfg.Path, paths...); err != nil {
		return err
	}

	return nil
}

func signSingleBinary(cfg SigningConfig) error {
	m, err := macho.NewFile(cfg.Path)
	if err != nil {
		return err
	}

	// check there already isn't a LcCodeSignature loader already (if there is, bail)
	if m.HasCodeSigningCmd() {
		if err := m.RemoveSigningContent(); err != nil {
			return fmt.Errorf("unable to remove existing code signature: %+v", err)
		}
	}

	entitlementsXML := ""
	if cfg.Entitlements != "" {
		data, err := os.ReadFile(cfg.Entitlements)
		if err != nil {
			return err
		}
		entitlementsXML = string(data)
	}

	// (patch) add empty LcCodeSignature loader (offset and size references are not set)
	if err = m.AddEmptyCodeSigningCmd(); err != nil {
		return err
	}

	// first pass: add the signed data with the dummy loader
	superBlobSize, sbBytes, err := sign.GenerateSigningSuperBlob(cfg.Identity, m, cfg.SigningMaterial, entitlementsXML, 0)
	if err != nil {
		return fmt.Errorf("failed to add signing data on pass=1: %w", err)
	}

	// (patch) make certain offset and size references to the superblob are finalized in the binary
	if err = sign.UpdateSuperBlobOffsetReferences(m, uint64(len(sbBytes))); err != nil {
		return err
	}

	// second pass: now that all of the sizing is right, let's do it again with the final contents (replacing the hashes and signature)
	if _, sbBytes, err = sign.GenerateSigningSuperBlob(cfg.Identity, m, cfg.SigningMaterial, entitlementsXML, superBlobSize); err != nil {
		return fmt.Errorf("failed to add signing data on pass=2: %w", err)
	}

	// (patch) append the superblob to the __LINKEDIT section

	codeSigningCmd, _, err := m.CodeSigningCmd()
	if err != nil {
		return err
	}

	if err = m.Patch(sbBytes, len(sbBytes), uint64(codeSigningCmd.DataOffset)); err != nil {
		return fmt.Errorf("failed to patch super blob onto macho binary: %w", err)
	}

	return nil
}

func IsSigned(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	if macholibre.IsUniversalMachoBinary(f) {
		mf, err := blacktopMacho.NewFatFile(f)
		if mf == nil || err != nil {
			return false, fmt.Errorf("failed to parse universal macho binary: %w", err)
		}
		defer mf.Close()

		success := true
		for _, arch := range mf.Arches {
			sig := arch.CodeSignature()
			if sig == nil {
				return false, nil
			}

			success = success && len(sig.CMSSignature) > 0
		}

		return success, nil
	}

	mf, err := blacktopMacho.NewFile(f)
	if mf == nil || err != nil {
		return false, fmt.Errorf("failed to parse macho binary: %w", err)
	}

	defer mf.Close()

	sig := mf.CodeSignature()
	if sig == nil {
		return false, nil
	}

	return len(sig.CMSSignature) > 0, nil
}
