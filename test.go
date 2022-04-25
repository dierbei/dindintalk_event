package main

import "strings"

//
///
//
/*

 */

func isAddComment(line string) bool {
	if strings.HasPrefix(line, "+") {
		if strings.HasPrefix(strings.TrimSpace(line[1:]), "//") ||
			strings.HasPrefix(strings.TrimSpace(line[1:]), "/*") ||
			strings.HasPrefix(strings.TrimSpace(line[1:]), "///") ||
			strings.HasPrefix(strings.TrimSpace(line[1:]), "*") {
			return true
		}
	}
	return false
}

//
//
///
