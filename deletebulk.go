package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

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

// deleteUsersBulkHandlerGin removes many clients with one config write and one
// apply. The apply also refills the spare stock. Spare blocks are never
// matched: removeClientFromConfig only looks at "### Client" markers.
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

	// Pass 1, in memory: drop each name's block and note which client files
	// exist. A name is not_found when it has neither.
	filesOf := make([][]string, len(names))
	blockRemoved := false
	for i, name := range names {
		var hadBlock bool
		content, hadBlock = removeClientFromConfig(content, name)
		blockRemoved = blockRemoved || hadBlock
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
	if blockRemoved {
		if err := os.WriteFile(WG_CONFIG_FILE, content, 0600); err != nil {
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
