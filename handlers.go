package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"go.uber.org/zap"
)

// Constants for supported SFTP request methods
const (
	SSH_FXP_REMOVE   = "Remove"
	SSH_FXP_RENAME   = "Rename"
	SSH_FXP_MKDIR    = "Mkdir"
	SSH_FXP_RMDIR    = "Rmdir"
	SSH_FXP_SET_STAT = "Setstat"
)

// SftpHandler is used by sftp.NewRequestServer to handle requests.
// It uses the OS filesystem but enforces virtual root + permission checks.
type SftpHandler struct {
	user   *User
	logger *zap.SugaredLogger
}

// resolvePath returns absolute canonical path for requested path inside user's root.
// It prevents escaping root by path traversal (../) or weird absolute requests.
// relative to the user's configured root directory.
func (h *SftpHandler) resolvePath(requested string) (string, error) {
	h.logger.Infof("Resolving path for request: %s", requested)

	// Base directory under which all user roots must live
	baseRoot := getEnvOrDefault("BASE_FS_ROOT", "./data/fs")

	// Normalize incoming path separators for the current OS
	req := filepath.FromSlash(requested)

	// Strip any leading volume or leading separators so the request is always treated as relative.
	if vol := filepath.VolumeName(req); vol != "" {
		req = strings.TrimPrefix(req, vol)
	}
	req = strings.TrimPrefix(req, string(filepath.Separator))
	req = strings.TrimPrefix(req, "/")

	// Clean up any ../ or ./ sequences in the requested path itself
	req = filepath.Clean(req)

	// Treat root-like requests as empty relative path so we map "/" -> user root
	if req == "." || req == string(filepath.Separator) || req == "/" || req == "" {
		req = ""
	}

	// Determine user's root. If not set or invalid, allocate under BASE_FS_ROOT/<username>
	userRoot := filepath.FromSlash(strings.TrimSpace(h.user.RootPath))
	if userRoot == "" {
		userRoot = filepath.Join(baseRoot, h.user.Username)
	}

	// Resolve absolute paths
	baseAbs, err := filepath.Abs(baseRoot)
	if err != nil {
		h.logger.Errorf("Error resolving base root absolute path: %v", err)
		return "", err
	}
	userRootAbs, err := filepath.Abs(userRoot)
	if err != nil {
		h.logger.Errorf("Error resolving user's root absolute path: %v", err)
		return "", err
	}

	// Ensure user's root is inside baseRoot. If not, rebase it under baseRoot.
	relToBase, rerr := filepath.Rel(baseAbs, userRootAbs)
	if rerr != nil || strings.HasPrefix(relToBase, "..") || relToBase == ".." {
		h.logger.Warnf("User root %s is outside BASE_FS_ROOT; rebasing to %s", userRootAbs, baseAbs)
		userRootAbs = filepath.Join(baseAbs, h.user.Username)
	}

	// Ensure the user root directory exists
	if mkerr := os.MkdirAll(userRootAbs, 0755); mkerr != nil {
		h.logger.Warnf("Failed to create user root dir (%s): %v", userRootAbs, mkerr)
	}

	// Update in-memory user root so subsequent calls use the resolved path
	h.user.RootPath = userRootAbs

	// If req is empty it means client asked for the user's root (e.g. "/")
	var joined string
	if req == "" {
		joined = userRootAbs
	} else {
		joined = filepath.Join(userRootAbs, req)
	}

	abs, err := filepath.Abs(joined)
	if err != nil {
		h.logger.Errorf("Error resolving absolute path: %v", err)
		return "", err
	}

	// Ensure the resolved path is within the user's root directory
	rel, err := filepath.Rel(userRootAbs, abs)
	if err != nil {
		h.logger.Errorf("Error getting relative path: %v", err)
		return "", errors.New("access denied")
	}
	if strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		h.logger.Warnf("Attempt to escape root directory: %s -> %s", requested, abs)
		return "", errors.New("access denied")
	}

	h.logger.Infof("Resolved path: %s", abs)
	return abs, nil
}

// hasPermission checks if the user has the specified permission.
func (h *SftpHandler) hasPermission(perm Permission) bool {
	hasPerm := h.user.Perms&perm != 0
	h.logger.Debugf("Checking permission [%s] for user %s: %v", perm, h.user.Username, hasPerm)
	return hasPerm
}
func (p Permission) String() string {
	switch p {
	case PermRead:
		return "read"
	case PermWrite:
		return "write"
	case PermDelete:
		return "delete"
	case PermList:
		return "list"
	default:
		return "unknown"
	}
}

// Fileread reads a file from the user's root directory.
// Handles download/open-for-read requests
func (h *SftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	h.logger.Debugf("[FileRead] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.hasPermission(PermRead) {
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

// Filewrite writes a file to the user's root directory.
// Handles upload/open-for-write requests
func (h *SftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	h.logger.Debugf("[Filewrite] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.hasPermission(PermWrite) {
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

// Filecmd handles other file commands like Delete, Rename, Mkdir, Rmdir
func (h *SftpHandler) Filecmd(r *sftp.Request) error {
	h.logger.Debugf("[Filecmd] User: %s, Method: %s, Path: %s", h.user.Username, r.Method, r.Filepath)
	// Resolve the absolute path for the requested file
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving file path: %v", err)
		return err
	}
	switch r.Method {
	case SSH_FXP_REMOVE:
		if !h.hasPermission(PermDelete) {
			h.logger.Warnf("Delete permission denied for user: %s", h.user.Username)
			return os.ErrPermission
		}
		// Handle file deletion
		if err := os.Remove(absPath); err != nil {
			h.logger.Errorf("Error deleting file: %v", err)
			return err
		}
	case SSH_FXP_RENAME:
		if !h.hasPermission(PermWrite) {
			h.logger.Warnf("Write permission denied for user: %s", h.user.Username)
			return os.ErrPermission
		}
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
		if !h.hasPermission(PermWrite) {
			h.logger.Warnf("Write permission denied for user: %s", h.user.Username)
			return os.ErrPermission
		}
		// Handle directory creation
		if err := os.MkdirAll(absPath, 0755); err != nil {
			h.logger.Errorf("Error creating directory: %v", err)
			return err
		}
	case SSH_FXP_RMDIR:
		if !h.hasPermission(PermDelete) {
			h.logger.Warnf("Delete permission denied for user: %s", h.user.Username)
			return os.ErrPermission
		}
		// Handle directory removal
		if err := os.RemoveAll(absPath); err != nil {
			h.logger.Errorf("Error removing directory: %v", err)
			return err
		}
	case SSH_FXP_SET_STAT:
		// Apply Setstat attributes best-effort with virtual-root safety and permission checks.
		if !h.hasPermission(PermWrite) {
			h.logger.Warnf("Setstat denied (write permission required) for user: %s", h.user.Username)
			return os.ErrPermission
		}
		attrs := r.Attributes()
		if attrs == nil {
			h.logger.Debugf("[Setstat] No attributes provided for %s", absPath)
			return nil
		}
		// 1) Permissions (Mode)
		if attrs.Mode != 0 {
			perm := os.FileMode(attrs.Mode & 0o777)
			if err := os.Chmod(absPath, perm); err != nil {
				h.logger.Errorf("[Setstat] Chmod failed on %s: %v", absPath, err)
				return err
			}
			h.logger.Debugf("[Setstat] Applied chmod %04o to %s", uint32(perm), absPath)
		}
		// 2) Times (Atime/Mtime)
		if attrs.Atime != 0 || attrs.Mtime != 0 {
			// If only one provided, reuse it for the other to keep API simple.
			at := attrs.Atime
			mt := attrs.Mtime
			if at == 0 {
				at = mt
			}
			if mt == 0 {
				mt = at
			}
			atime := time.Unix(int64(at), 0)
			mtime := time.Unix(int64(mt), 0)
			if err := os.Chtimes(absPath, atime, mtime); err != nil {
				h.logger.Errorf("[Setstat] Chtimes failed on %s: %v", absPath, err)
				return err
			}
			h.logger.Debugf("[Setstat] Applied chtimes atime=%v mtime=%v to %s", atime, mtime, absPath)
		}
		// 3) Ownership (UID/GID) — unsupported on Windows.
		if runtime.GOOS != "windows" && (attrs.UID != 0 || attrs.GID != 0) {
			if err := os.Chown(absPath, int(attrs.UID), int(attrs.GID)); err != nil {
				h.logger.Errorf("[Setstat] Chown failed on %s: %v", absPath, err)
				return err
			}
			h.logger.Debugf("[Setstat] Applied chown uid=%d gid=%d to %s", attrs.UID, attrs.GID, absPath)
		} else if runtime.GOOS == "windows" && (attrs.UID != 0 || attrs.GID != 0) {
			h.logger.Debugf("[Setstat] Skipping chown on Windows for %s (uid=%d gid=%d)", absPath, attrs.UID, attrs.GID)
		}
		// 4) Size (truncate). Ambiguity: FileStat lacks flags; to avoid destructive truncation to 0
		// when size is not explicitly set, we only act when Size > 0.
		if attrs.Size > 0 {
			// Ensure it is a regular file before truncating
			fi, statErr := os.Stat(absPath)
			if statErr != nil {
				h.logger.Errorf("[Setstat] Stat before truncate failed on %s: %v", absPath, statErr)
				return statErr
			}
			if fi.Mode().IsRegular() {
				if err := os.Truncate(absPath, int64(attrs.Size)); err != nil {
					h.logger.Errorf("[Setstat] Truncate failed on %s: %v", absPath, err)
					return err
				}
				h.logger.Debugf("[Setstat] Applied truncate size=%d to %s", attrs.Size, absPath)
			} else {
				h.logger.Warnf("[Setstat] Skip truncate: %s is not a regular file", absPath)
			}
		} else if attrs.Size == 0 {
			// We cannot distinguish between 'set size to 0' and 'size not provided' without flags in this API.
			h.logger.Debugf("[Setstat] Size=0 ignored for safety on %s (ambiguous: not applying truncate)", absPath)
		}
		return nil
	default:
		h.logger.Warnf("Unsupported file command: %s", r.Method)
		return os.ErrInvalid
	}
	return nil
}

// Filelist lists files in a directory within the user's root directory.
// Handles directory listing requests
func (h *SftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	h.logger.Debugf("[Filelist] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.hasPermission(PermList) {
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
	// For empty directories, return (0, nil) on the first call so some clients
	// (e.g., WinSCP) don't interpret immediate EOF as an error.
	if len(l.fis) == 0 && offset == 0 {
		return 0, nil
	}
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

// Lstat implements sftp.LstatFileLister to handle SSH_FXP_LSTAT using our
// virtual root resolution. It returns a ListerAt that yields exactly one
// os.FileInfo corresponding to the requested path.
func (h *SftpHandler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	// WinSCP issues LSTAT when entering directories; ensure we resolve the
	// virtual path and do not leak the raw request path.
	h.logger.Debugf("[Lstat] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.hasPermission(PermList) && !h.hasPermission(PermRead) {
		h.logger.Warnf("Lstat permission denied for user: %s", h.user.Username)
		return nil, os.ErrPermission
	}
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving lstat path: %v", err)
		return nil, err
	}
	fi, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			h.logger.Warnf("Path does not exist for lstat: %s", absPath)
			return nil, os.ErrNotExist
		}
		h.logger.Errorf("Error lstat path: %v", err)
		return nil, err
	}
	return listerFromFileInfo([]os.FileInfo{fi}), nil
}

// Stat implements sftp.StatFileLister to handle SSH_FXP_STAT using our
// virtual root resolution. It returns a ListerAt that yields exactly one
// os.FileInfo corresponding to the requested path.
func (h *SftpHandler) Stat(r *sftp.Request) (sftp.ListerAt, error) {
	// Ensure we resolve the virtual path and do not leak the raw request path.
	h.logger.Debugf("[Stat] User: %s, Path: %s", h.user.Username, r.Filepath)
	if !h.hasPermission(PermList) && !h.hasPermission(PermRead) {
		h.logger.Warnf("Stat permission denied for user: %s", h.user.Username)
		return nil, os.ErrPermission
	}
	absPath, err := h.resolvePath(r.Filepath)
	if err != nil {
		h.logger.Errorf("Error resolving stat path: %v", err)
		return nil, err
	}
	fi, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			h.logger.Warnf("Path does not exist for stat: %s", absPath)
			return nil, os.ErrNotExist
		}
		h.logger.Errorf("Error stat path: %v", err)
		return nil, err
	}
	return listerFromFileInfo([]os.FileInfo{fi}), nil
}
