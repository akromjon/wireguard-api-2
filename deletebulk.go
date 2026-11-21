package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// DeleteBulkResult is the outcome of one requested name in
// POST /api/users/delete-bulk.
type DeleteBulkResult struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Status  string `json:"status"` // deleted, not_found, error
	Message string `json:"message,omitempty"`
}

const (
	deleteStatusDeleted  = "deleted"
	deleteStatusNotFound = "not_found"
	deleteStatusError    = "error"
)

// clientFileVariants lists every client file path a single delete removes for
// a name.
func clientFileVariants(name string) []string {
	return []string{
		clientFilePath(name),
		filepath.Join(WIREGUARD_CLIENTS, "wg0-client-"+name+".conf"),
		filepath.Join(WIREGUARD_CLIENTS, "awg0-client-"+name+".conf"),
		filepath.Join(WIREGUARD_CLIENTS, name+".conf"),
	}
}

// clientBlockName returns the name on a block's "### Client" marker line,
// taken whole (nothing trimmed) like the single-delete patterns match it. ok is
// false for a spare block.
func clientBlockName(block string) (name string, ok bool) {
	for _, line := range strings.Split(block, "\n") {
		if !isMarkerLine(strings.TrimRight(line, "\r")) {
			continue
		}
		if !strings.HasPrefix(line, clientMarker) {
			return "", false
		}
		return strings.TrimPrefix(line, clientMarker), true
	}
	return "", false
}

// deleteUsersBulkHandlerGin removes many clients with one config write and one
// apply. The apply also refills the spare stock. Spare blocks are never
// matched: only "### Client" markers are.
func deleteUsersBulkHandlerGin(c *gin.Context) {
	var req AddUsersBulkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request payload"})
		return
	}
	if msg := validateBulkNames(req.Names); msg != "" {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Message: msg})
		return
	}

	results, status, errMsg := deleteBulkLocked(req.Names)
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	data := gin.H{
		"deleted":   counts[deleteStatusDeleted],
		"not_found": counts[deleteStatusNotFound],
		"failed":    counts[deleteStatusError],
		"results":   results,
	}
	if status != http.StatusOK {
		c.JSON(status, APIResponse{Success: false, Message: errMsg, Data: data})
		return
	}
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Deleted %d, not found %d, failed %d of %d clients",
			counts[deleteStatusDeleted], counts[deleteStatusNotFound], counts[deleteStatusError], len(req.Names)),
		Data: data,
	})
}

// deleteBulkLocked does the work of one delete-bulk request under a single
// wgConfigMutex hold and returns the per-name results and the HTTP status.
func deleteBulkLocked(names []string) ([]DeleteBulkResult, int, string) {
	wgConfigMutex.Lock()
	defer wgConfigMutex.Unlock()

	results := make([]DeleteBulkResult, len(names))
	// markAllError reports every name that would have been deleted as failed.
	markAllError := func(msg string) {
		for i := range results {
			if results[i].Status == deleteStatusDeleted {
				results[i] = DeleteBulkResult{Name: names[i], Status: deleteStatusError, Message: msg}
			}
		}
	}

	content, err := os.ReadFile(WG_CONFIG_FILE)
	if err != nil {
		for i, name := range names {
			results[i] = DeleteBulkResult{Name: name, Status: deleteStatusError, Message: fmt.Sprintf("failed to read WireGuard config: %v", err)}
		}
		return results, http.StatusInternalServerError, fmt.Sprintf("failed to read WireGuard config: %v", err)
	}

	// Pass 1, in memory: pick each name's blocks and note which client files
	// exist. A name is not_found when it has neither. Like single delete
	// (removeClientFromConfig), a name takes the blocks of the first of its
	// marker forms still present, all of them; one pass over the blocks then
	// drops every picked marker.
	header, blocks := splitBlocks(string(content))
	left := make(map[string]int) // client marker name -> blocks not yet picked
	for _, b := range blocks {
		if m, ok := clientBlockName(b); ok {
			left[m]++
		}
	}
	drop := make(map[string]bool)
	filesOf := make([][]string, len(names))
	for i, name := range names {
		hadBlock := false
		for _, form := range clientNameForms(name) {
			if left[form] > 0 {
				drop[form], left[form], hadBlock = true, 0, true
				break
			}
		}
		for _, p := range clientFileVariants(name) {
			if fileExists(p) {
				filesOf[i] = append(filesOf[i], p)
			}
		}
		if hadBlock || len(filesOf[i]) > 0 {
			results[i] = DeleteBulkResult{Name: name, Success: true, Status: deleteStatusDeleted}
		} else {
			results[i] = DeleteBulkResult{Name: name, Success: true, Status: deleteStatusNotFound}
		}
	}

	// Write the conf once, before touching any client file.
	if len(drop) > 0 {
		var out strings.Builder
		out.WriteString(header)
		for _, b := range blocks {
			if m, ok := clientBlockName(b); !ok || !drop[m] {
				out.WriteString(b)
			}
		}
		if err := os.WriteFile(WG_CONFIG_FILE, []byte(out.String()), 0600); err != nil {
			msg := fmt.Sprintf("failed to update server config: %v", err)
			markAllError(msg)
			return results, http.StatusInternalServerError, msg
		}
	}

	// Pass 2: remove the client files. A failure marks only that name.
	for i, paths := range filesOf {
		for _, p := range paths {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				results[i] = DeleteBulkResult{
					Name: names[i], Status: deleteStatusError,
					Message: fmt.Sprintf("failed to delete client config: %v", err),
				}
				break
			}
		}
	}

	// Exactly one apply per request, even when every name was not_found: it
	// refills the spare stock and re-applies the file, so an earlier failed
	// apply heals here (same as add-bulk).
	if err := applyConfigLocked(); err != nil {
		log.Printf("delete-bulk: config apply failed: %v", err)
		// The blocks are already gone from the file, so a retry reports
		// not_found and the next successful apply drops the peers.
		msg := fmt.Sprintf("failed to apply config: %v", err)
		markAllError(msg)
		return results, http.StatusInternalServerError, msg
	}
	return results, http.StatusOK, ""
}
