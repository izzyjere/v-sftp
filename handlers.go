package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"go.uber.org/zap"
)
// Constants for supported SFTP request methods
const (
	SSH_FXP_REMOVE = "Remove"
	SSH_FXP_RENAME = "Rename"
	SSH_FXP_MKDIR  = "Mkdir"
	SSH_FXP_RMDIR  = "Rmdir"
)

// SftpHandler will be used by sftp.NewRequestServer to handle requests.
// It uses the OS filesystem but enforces virtual root + permission checks.
type SftpHandler struct {
	user   *User
	logger *zap.SugaredLogger
}

// resolvePath returns absolute canonical path for requested path inside user's root.
// It prevents escaping root by path traversal (../) or weird absolute requests.
func (h *SftpHandler) resolvePath(requested string) (string, error) {
	h.logger.Infof("Resolving path for request: %s", requested)
	// Clean the requested path to remove any ../ or ./ components
	// Normalize separators and ensure requested is treated as relative to root
	// ensure starting slash
	req := filepath.Clean("/" + strings.ReplaceAll(requested, "/", string(filepath.Separator)))
	// Join with user's root path
	req = filepath.Join(h.user.RootPath, req)
	// Get absolute path
	abs, err := filepath.Abs(req)
	if err != nil {
		h.logger.Errorf("Error resolving absolute path: %v", err)
		return "", err
	}
	rootAbs, err := filepath.Abs(h.user.RootPath)
	if err != nil {
		h.logger.Errorf("Error resolving user's root absolute path: %v", err)
		return "", err
	}
	// Ensure the resolved path is within the user's root directory
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		h.logger.Errorf("Error getting relative path: %v", err)
		return "", err
	}
	// If rel starts with "..", the requested path is outside the root
	if strings.HasPrefix(rel, "..") {
		h.logger.Warnf("Attempt to escape root directory: %s", requested)
		return "", errors.New("access denied")
	}
	h.logger.Infof("Resolved path: %s", abs)
	return abs, nil
}

// HasPermission checks if the user has the specified permission.
func (h *SftpHandler) HasPermission(perm Permission) bool {
	hasPerm := h.user.Perms&perm != 0
	h.logger.Debugf("Checking permission %d for user %s: %v", perm, h.user.Username, hasPerm)
	return hasPerm
}

// FileRead reads a file from the user's root directory.
// Handles download/open-for-read requests
func (h *SftpHandler) FileRead(r *sftp.Request) (io.ReaderAt, error) {
	h.logger.Debugf("[FileRead] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.HasPermission(PermRead) {
		h.logger.Warnf("Read permission denied for user: %s", h.user.Username)
		return nil, os.ErrPermission
	}

	// Resolve the absolute path for the requested file
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving file path: %v", err)
		return nil, err
	}

	// Open the file for reading
	file, err := os.Open(absPath)
	if err != nil {
		h.logger.Errorf("Error opening file: %v", err)
		return nil, err
	}
	return file, nil
}

// FileWrite writes a file to the user's root directory.
// Handles upload/open-for-write requests
func (h *SftpHandler) FileWrite(r *sftp.Request) (io.WriterAt, error) {
	h.logger.Debugf("[FileWrite] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.HasPermission(PermWrite) {
		h.logger.Warnf("Write permission denied for user: %s", h.user.Username)
		return nil, os.ErrPermission
	}
	// Resolve the absolute path for the requested file
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving file path: %v", err)
		return nil, err
	}
	// Ensure the directory exists
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		h.logger.Errorf("Error creating directories: %v", err)
		return nil, err
	}
	// Open the file for writing (create if not exists)
	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		h.logger.Errorf("Error opening file for write: %v", err)
		return nil, err
	}
	return file, nil
}

// FileCmd handles other file commands like Delete, Rename, Mkdir, Rmdir
func (h *SftpHandler) FileCmd(r *sftp.Request) error {
	h.logger.Debugf("[FileCmd] User: %s, Method: %s, Path: %s", h.user.Username, r.Method, r.Filepath)
	if !h.HasPermission(PermWrite) {
		h.logger.Warnf("Write permission denied for user: %s", h.user.Username)
		return os.ErrPermission
	}
	// Resolve the absolute path for the requested file
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving file path: %v", err)
		return err
	}
	switch r.Method {
	case SSH_FXP_REMOVE:
		// Handle file deletion
		if err := os.Remove(absPath); err != nil {
			h.logger.Errorf("Error deleting file: %v", err)
			return err
		}
	case SSH_FXP_RENAME:
		newPath, err := h.resolvePath(r.Target)
		if err != nil {
			h.logger.Errorf("Error resolving new file path: %v", err)
			return err
		}
		// Handle file renaming
		if err := os.Rename(absPath, newPath); err != nil {
			h.logger.Errorf("Error renaming file: %v", err)
			return err
		}
	case SSH_FXP_MKDIR:
		// Handle directory creation
		if err := os.MkdirAll(absPath, 0755); err != nil {
			h.logger.Errorf("Error creating directory: %v", err)
			return err
		}
	case SSH_FXP_RMDIR:
		// Handle directory removal
		if err := os.RemoveAll(absPath); err != nil {
			h.logger.Errorf("Error removing directory: %v", err)
			return err
		}
	default:
		h.logger.Warnf("Unsupported file command: %s", r.Method)
		return os.ErrInvalid
	}
	return nil
}

// FileList lists files in a directory within the user's root directory.
// Handles directory listing requests
func (h *SftpHandler) FileList(r *sftp.Request) (sftp.ListerAt, error) {
	h.logger.Debugf("[FileList] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.HasPermission(PermList) {
		h.logger.Warnf("List permission denied for user: %s", h.user.Username)
		return nil, os.ErrPermission
	}
	// Resolve the absolute path for the requested directory
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving directory path: %v", err)
		return nil, err
	}
	// Read the directory contents
	fis, err := os.Open(absPath)
	if err != nil {
		h.logger.Errorf("Error reading directory: %v", err)
		return nil, err
	}
	defer fis.Close()
	fisList, err := fis.Readdir(-1)
	if err != nil {
		h.logger.Errorf("Error listing directory contents: %v", err)
		return nil, err
	}
	return listerFromFileInfo(fisList), nil
}

// helper: convert []os.FileInfo to sftp.ListerAt
type fileInfoLister struct{ fis []os.FileInfo }

func (l *fileInfoLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.fis)) {
		return 0, io.EOF
	}
	n := copy(ls, l.fis[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}
func listerFromFileInfo(fis []os.FileInfo) sftp.ListerAt { return &fileInfoLister{fis: fis} }
